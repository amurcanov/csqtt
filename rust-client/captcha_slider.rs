// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::captcha::{
    CaptchaSession, RateLimit, device_info, response_object, slider_check, slider_request,
    slider_saved_profile, value_string,
};
use anyhow::{Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use image::{DynamicImage, GenericImageView, Pixel, Rgba};
use rand::RngExt;
use serde::Serialize;
use serde_json::{Value, json};
use std::cmp::Ordering;

struct SliderPuzzle {
    image: DynamicImage,
    size: usize,
    swaps: Vec<usize>,
    attempts: usize,
}

#[derive(Clone)]
struct SliderGuess {
    index: usize,
    swaps: Vec<usize>,
    score_luma: u64,
    score_rgb: u64,
    score_text: f64,
    consensus_rank: usize,
}

pub(crate) async fn solve_slider(
    session: &CaptchaSession<'_>,
    session_token: &str,
    browser_fp: &str,
    hash: &str,
    settings: &str,
    debug_info: &str,
) -> Result<String> {
    let response = slider_request(
        session,
        "captchaNotRobot.getContent",
        &[
            ("session_token", session_token),
            ("domain", "vk.com"),
            ("adFp", ""),
            ("access_token", ""),
            ("captcha_settings", settings),
        ],
    )
    .await
    .map_err(|error| anyhow!("slider getContent failed: {error}"))?;
    let puzzle = parse_puzzle(&response)?;
    crate::log_error!(
        "[КАПЧА] v2 slider puzzle decoded: grid={} attempts={} swaps={}",
        puzzle.size,
        puzzle.attempts,
        puzzle.swaps.len()
    );
    let size = puzzle.size;
    let swaps = puzzle.swaps;
    let attempts = puzzle.attempts;
    let guesses = crate::cpu_task::run("csqtt-captcha-slider", move || {
        rank_guesses(&puzzle.image, size, &swaps)
    })
    .await?;
    let limit = attempts.min(guesses.len());
    if limit == 0 {
        bail!("slider has no attempts available");
    }
    crate::log_error!(
        "[КАПЧА] v2 slider guesses ranked: total={} limit={limit}",
        guesses.len()
    );
    let device = device_info(slider_saved_profile(session));
    slider_request(
        session,
        "captchaNotRobot.componentDone",
        &[
            ("session_token", session_token),
            ("domain", "vk.com"),
            ("adFp", ""),
            ("access_token", ""),
            ("browser_fp", browser_fp),
            ("device", device),
        ],
    )
    .await
    .map_err(|error| anyhow!("captcha componentDone failed: {error}"))?;
    for (attempt, guess) in guesses.iter().take(limit).enumerate() {
        crate::log_error!(
            "[КАПЧА] v2 slider attempt {}/{} (guess #{})",
            attempt + 1,
            limit,
            guess.index
        );
        let answer = json!({"value": guess.swaps}).to_string();
        let cursor = build_cursor(guess.index, guesses.len());
        let (status, success_token) = slider_check(
            session,
            session_token,
            browser_fp,
            hash,
            &answer,
            &cursor,
            debug_info,
        )
        .await?;
        if status.eq_ignore_ascii_case("ok") {
            if success_token.is_empty() {
                bail!("captcha success token not found");
            }
            crate::log_error!("[КАПЧА] v2 slider accepted on attempt {}", attempt + 1);
            return Ok(success_token);
        }
        if status.eq_ignore_ascii_case("error_limit") {
            return Err(RateLimit.into());
        }
    }
    bail!("slider guesses exhausted")
}

fn parse_puzzle(raw: &Value) -> Result<SliderPuzzle> {
    let response = response_object(raw)?;
    let status = value_string(response.get("status"));
    if !status.eq_ignore_ascii_case("ok") {
        bail!("slider getContent status: {status}");
    }
    let raw_image = value_string(response.get("image"));
    if raw_image.is_empty() {
        bail!("slider image missing");
    }
    let raw_steps = response
        .get("steps")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("slider steps missing"))?;
    let steps: Vec<usize> = raw_steps.iter().map(parse_number).collect::<Result<_>>()?;
    let (size, swaps, attempts) = split_steps(&steps)?;
    let data = STANDARD
        .decode(raw_image)
        .map_err(|error| anyhow!("decode slider image: {error}"))?;
    let image =
        image::load_from_memory(&data).map_err(|error| anyhow!("decode slider image: {error}"))?;
    Ok(SliderPuzzle {
        image,
        size,
        swaps,
        attempts,
    })
}

fn parse_number(value: &Value) -> Result<usize> {
    if let Some(value) = value.as_u64() {
        return usize::try_from(value).map_err(Into::into);
    }
    if let Some(value) = value.as_str() {
        return value.trim().parse().map_err(Into::into);
    }
    bail!("invalid numeric value: {value}")
}

// Real slider puzzles are 3..8 tiles per side; anything larger is either a
// protocol change or hostile input that would allocate a huge swap mapping.
const MAX_SLIDER_GRID: usize = 16;

fn split_steps(steps: &[usize]) -> Result<(usize, Vec<usize>, usize)> {
    if steps.len() < 3 {
        bail!("slider steps payload too short");
    }
    let size = steps[0];
    if size == 0 || size > MAX_SLIDER_GRID {
        bail!("invalid slider size: {size}");
    }
    let mut tail = steps[1..].to_vec();
    let mut attempts = 4;
    if !tail.len().is_multiple_of(2) {
        attempts = tail.pop().unwrap_or(4);
        crate::log_error!(
            "[КАПЧА] v2 slider payload had odd-length tail; fallback attempts={attempts}"
        );
    }
    if attempts == 0 {
        attempts = 4;
    }
    if tail.is_empty() || !tail.len().is_multiple_of(2) {
        bail!("invalid slider swap payload");
    }
    Ok((size, tail, attempts))
}

fn rank_guesses(
    image: &DynamicImage,
    grid_size: usize,
    swaps: &[usize],
) -> Result<Vec<SliderGuess>> {
    let candidate_count = swaps.len() / 2;
    if candidate_count == 0 {
        bail!("slider has no candidates");
    }
    let mut guesses = Vec::with_capacity(candidate_count);
    for index in 1..=candidate_count {
        let active = swaps[..(index * 2).min(swaps.len())].to_vec();
        let mapping = apply_swaps(grid_size, &active)?;
        guesses.push(SliderGuess {
            index,
            swaps: active,
            score_luma: seam_score_luma(image, grid_size, &mapping),
            score_rgb: 0,
            score_text: 0.0,
            consensus_rank: 0,
        });
    }
    let mut luma_order: Vec<_> = (0..candidate_count).collect();
    luma_order.sort_by_key(|&index| (guesses[index].score_luma, guesses[index].index));
    let mut luma_rank = vec![0; candidate_count + 1];
    for (rank, &index) in luma_order.iter().enumerate() {
        luma_rank[guesses[index].index] = rank;
    }
    let stage_two: Vec<_> = luma_order
        .into_iter()
        .take(candidate_count.min(12))
        .collect();
    let computed: Vec<Result<(usize, u64, f64)>> = stage_two
        .iter()
        .map(|&index| {
            let mapping = apply_swaps(grid_size, &guesses[index].swaps)?;
            let (rgb, text) = seam_score_rgb_text(image, grid_size, &mapping);
            Ok((index, rgb, text))
        })
        .collect();
    for result in computed {
        let (index, rgb, text) = result?;
        guesses[index].score_rgb = rgb;
        guesses[index].score_text = text;
    }
    let mut rgb_order = stage_two.clone();
    rgb_order.sort_by_key(|&index| (guesses[index].score_rgb, guesses[index].index));
    let mut text_order = stage_two.clone();
    text_order.sort_by(|&left, &right| {
        guesses[left]
            .score_text
            .partial_cmp(&guesses[right].score_text)
            .unwrap_or(Ordering::Equal)
            .then_with(|| guesses[left].index.cmp(&guesses[right].index))
    });
    let mut rgb_rank = vec![0; candidate_count + 1];
    let mut text_rank = vec![0; candidate_count + 1];
    let mut in_stage_two = vec![false; candidate_count + 1];
    for (rank, &index) in rgb_order.iter().enumerate() {
        rgb_rank[guesses[index].index] = rank;
        in_stage_two[guesses[index].index] = true;
    }
    for (rank, &index) in text_order.iter().enumerate() {
        text_rank[guesses[index].index] = rank;
    }
    for guess in &mut guesses {
        guess.consensus_rank = luma_rank[guess.index];
        if in_stage_two[guess.index] {
            guess.consensus_rank += rgb_rank[guess.index] + text_rank[guess.index];
        } else {
            guess.consensus_rank += candidate_count;
        }
    }
    guesses.sort_by_key(|guess| (guess.consensus_rank, guess.score_luma, guess.index));
    Ok(guesses)
}

fn apply_swaps(grid_size: usize, swaps: &[usize]) -> Result<Vec<usize>> {
    let tile_count = grid_size
        .checked_mul(grid_size)
        .ok_or_else(|| anyhow!("invalid slider tile count"))?;
    if tile_count == 0 {
        bail!("invalid slider tile count: {tile_count}");
    }
    if !swaps.len().is_multiple_of(2) {
        bail!("invalid slider swaps length: {}", swaps.len());
    }
    let mut mapping: Vec<_> = (0..tile_count).collect();
    for pair in swaps.chunks_exact(2) {
        if pair[0] >= tile_count || pair[1] >= tile_count {
            bail!("slider step out of range: {},{}", pair[0], pair[1]);
        }
        mapping.swap(pair[0], pair[1]);
    }
    Ok(mapping)
}

#[derive(Clone, Copy)]
struct Rect {
    min_x: u32,
    min_y: u32,
    max_x: u32,
    max_y: u32,
}

impl Rect {
    fn width(self) -> u32 {
        self.max_x - self.min_x
    }

    fn height(self) -> u32 {
        self.max_y - self.min_y
    }
}

fn tile_rect(image: &DynamicImage, grid_size: usize, index: usize) -> Rect {
    let (width, height) = image.dimensions();
    let column = index % grid_size;
    let row = index / grid_size;
    Rect {
        min_x: (column as u32 * width) / grid_size as u32,
        min_y: (row as u32 * height) / grid_size as u32,
        max_x: ((column as u32 + 1) * width) / grid_size as u32,
        max_y: ((row as u32 + 1) * height) / grid_size as u32,
    }
}

fn sample(image: &DynamicImage, destination: Rect, source: Rect, x: u32, y: u32) -> Rgba<u8> {
    let width = destination.width().max(1);
    let height = destination.height().max(1);
    // Rect math can round past the image edge when the grid exceeds the
    // bitmap; get_pixel would panic there, so clamp to the last pixel.
    let (image_width, image_height) = image.dimensions();
    let source_x = (source.min_x + (x - destination.min_x) * source.width() / width)
        .min(image_width.saturating_sub(1));
    let source_y = (source.min_y + (y - destination.min_y) * source.height() / height)
        .min(image_height.saturating_sub(1));
    image.get_pixel(source_x, source_y).to_rgba()
}

fn luma(pixel: Rgba<u8>) -> i32 {
    (299 * i32::from(pixel[0]) + 587 * i32::from(pixel[1]) + 114 * i32::from(pixel[2])) / 1000
}

fn pixel_diff(left: Rgba<u8>, right: Rgba<u8>) -> u64 {
    u64::from(left[0].abs_diff(right[0]))
        + u64::from(left[1].abs_diff(right[1]))
        + u64::from(left[2].abs_diff(right[2]))
}

fn seam_score_luma(image: &DynamicImage, grid_size: usize, mapping: &[usize]) -> u64 {
    let mut score = 0u64;
    for row in 0..grid_size {
        for column in 0..grid_size.saturating_sub(1) {
            let left_index = row * grid_size + column;
            let right_index = left_index + 1;
            let left_destination = tile_rect(image, grid_size, left_index);
            let right_destination = tile_rect(image, grid_size, right_index);
            let left_source = tile_rect(image, grid_size, mapping[left_index]);
            let right_source = tile_rect(image, grid_size, mapping[right_index]);
            for offset in 0..left_destination.height().min(right_destination.height()) {
                let y = left_destination.min_y + offset;
                let left = luma(sample(
                    image,
                    left_destination,
                    left_source,
                    left_destination.max_x - 1,
                    y,
                ));
                let right = luma(sample(
                    image,
                    right_destination,
                    right_source,
                    right_destination.min_x,
                    y,
                ));
                score += u64::from(left.abs_diff(right));
            }
        }
    }
    for row in 0..grid_size.saturating_sub(1) {
        for column in 0..grid_size {
            let top_index = row * grid_size + column;
            let bottom_index = (row + 1) * grid_size + column;
            let top_destination = tile_rect(image, grid_size, top_index);
            let bottom_destination = tile_rect(image, grid_size, bottom_index);
            let top_source = tile_rect(image, grid_size, mapping[top_index]);
            let bottom_source = tile_rect(image, grid_size, mapping[bottom_index]);
            for offset in 0..top_destination.width().min(bottom_destination.width()) {
                let x = top_destination.min_x + offset;
                let top = luma(sample(
                    image,
                    top_destination,
                    top_source,
                    x,
                    top_destination.max_y - 1,
                ));
                let bottom = luma(sample(
                    image,
                    bottom_destination,
                    bottom_source,
                    x,
                    bottom_destination.min_y,
                ));
                score += u64::from(top.abs_diff(bottom));
            }
        }
    }
    score
}

fn seam_score_rgb_text(image: &DynamicImage, grid_size: usize, mapping: &[usize]) -> (u64, f64) {
    let (_, height) = image.dimensions();
    let centers = [
        0.2 * f64::from(height),
        0.5 * f64::from(height),
        0.8 * f64::from(height),
    ];
    let sigma = (f64::from(height) * 0.14).max(1.0);
    let weight = |y: u32| {
        let distance = centers
            .iter()
            .map(|center| (f64::from(y) - center).abs())
            .fold(f64::INFINITY, f64::min);
        1.0 + 3.0 * (-(distance * distance) / (2.0 * sigma * sigma)).exp()
    };
    let mut rgb_score = 0u64;
    let mut text_score = 0.0;
    for row in 0..grid_size {
        for column in 0..grid_size.saturating_sub(1) {
            let left_index = row * grid_size + column;
            let right_index = left_index + 1;
            let left_destination = tile_rect(image, grid_size, left_index);
            let right_destination = tile_rect(image, grid_size, right_index);
            let left_source = tile_rect(image, grid_size, mapping[left_index]);
            let right_source = tile_rect(image, grid_size, mapping[right_index]);
            for offset in 0..left_destination.height().min(right_destination.height()) {
                let y = left_destination.min_y + offset;
                let left = sample(
                    image,
                    left_destination,
                    left_source,
                    left_destination.max_x - 1,
                    y,
                );
                let right = sample(
                    image,
                    right_destination,
                    right_source,
                    right_destination.min_x,
                    y,
                );
                rgb_score += pixel_diff(left, right);
                text_score += weight(y) * f64::from(left[2].abs_diff(right[2]));
            }
        }
    }
    for row in 0..grid_size.saturating_sub(1) {
        for column in 0..grid_size {
            let top_index = row * grid_size + column;
            let bottom_index = (row + 1) * grid_size + column;
            let top_destination = tile_rect(image, grid_size, top_index);
            let bottom_destination = tile_rect(image, grid_size, bottom_index);
            let top_source = tile_rect(image, grid_size, mapping[top_index]);
            let bottom_source = tile_rect(image, grid_size, mapping[bottom_index]);
            for offset in 0..top_destination.width().min(bottom_destination.width()) {
                let x = top_destination.min_x + offset;
                let top = sample(
                    image,
                    top_destination,
                    top_source,
                    x,
                    top_destination.max_y - 1,
                );
                let bottom = sample(
                    image,
                    bottom_destination,
                    bottom_source,
                    x,
                    bottom_destination.min_y,
                );
                rgb_score += pixel_diff(top, bottom);
                text_score += 0.65 * f64::from(top[2].abs_diff(bottom[2]));
            }
        }
    }
    (rgb_score, text_score)
}

#[derive(Serialize)]
struct CursorPoint {
    x: i32,
    y: i32,
}

fn build_cursor(candidate_index: usize, candidate_count: usize) -> String {
    if candidate_count == 0 {
        return "[]".to_owned();
    }
    let candidate_index = candidate_index.clamp(1, candidate_count);
    let mut random = rand::rng();
    let start_x = 570 + random.random_range(0..40);
    let start_y = 875 + random.random_range(0..30);
    let denominator = candidate_count.saturating_sub(1).max(1);
    let target_x = 734
        + (937 - 734) * (candidate_index - 1) as i32 / denominator as i32
        + random.random_range(-5..5);
    let target_y = 655 + random.random_range(0..14);
    let mut points = Vec::with_capacity(28);
    for _ in 0..random.random_range(1..4) {
        points.push(CursorPoint {
            x: start_x + random.random_range(-2..3),
            y: start_y + random.random_range(-2..3),
        });
    }
    let transit_steps = random.random_range(2..5);
    let control_x = f64::from(start_x + target_x) / 2.0 + f64::from(random.random_range(-30..30));
    let control_y = f64::from(start_y + target_y) / 2.0 - f64::from(random.random_range(10..40));
    for index in 1..=transit_steps {
        let time = f64::from(index) / f64::from(transit_steps + 1);
        let x = (1.0 - time).powi(2) * f64::from(start_x)
            + 2.0 * time * (1.0 - time) * control_x
            + time.powi(2) * f64::from(target_x);
        let y = (1.0 - time).powi(2) * f64::from(start_y)
            + 2.0 * time * (1.0 - time) * control_y
            + time.powi(2) * f64::from(target_y);
        let jitter = ((1.0 - time) * 8.0) as i32 + 2;
        points.push(CursorPoint {
            x: x.round() as i32 + random.random_range(-jitter..=jitter),
            y: y.round() as i32 + random.random_range(-jitter..=jitter),
        });
    }
    let approach_steps = random.random_range(4..8);
    let previous = points
        .last()
        .map(|point| (point.x, point.y))
        .unwrap_or((start_x, start_y));
    for index in 1..=approach_steps {
        let time = f64::from(index) / f64::from(approach_steps);
        points.push(CursorPoint {
            x: previous.0
                + (time * f64::from(target_x - previous.0)).round() as i32
                + random.random_range(-2..3),
            y: previous.1
                + (time * f64::from(target_y - previous.1)).round() as i32
                + random.random_range(-2..3),
        });
    }
    for _ in 0..random.random_range(3..8) {
        points.push(CursorPoint {
            x: target_x + random.random_range(-3..4),
            y: target_y + random.random_range(-3..4),
        });
    }
    serde_json::to_string(&points).unwrap_or_else(|_| "[]".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_swap_sequence() {
        assert_eq!(apply_swaps(2, &[0, 3, 1, 2]).unwrap(), vec![3, 2, 1, 0]);
    }

    #[test]
    fn splits_attempt_count() {
        assert_eq!(
            split_steps(&[3, 0, 1, 2, 3, 5]).unwrap(),
            (3, vec![0, 1, 2, 3], 5)
        );
    }

    #[test]
    fn cursor_has_human_path() {
        let value: Value = serde_json::from_str(&build_cursor(2, 5)).unwrap();
        assert!(value.as_array().unwrap().len() >= 10);
    }
}
