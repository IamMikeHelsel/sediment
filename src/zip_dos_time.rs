// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DosDateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DosTimestampError {
    InvalidDate,
    InvalidTime,
    OddSecond,
}

fn is_leap_year(year: u16) -> bool {
    (year % 4 == 0) && ((year % 100 != 0) || (year % 400 == 0))
}

fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

pub fn decode_dos(date: u16, time: u16) -> Result<DosDateTime, DosTimestampError> {
    let year_offset = (date >> 9) & 0x7F;
    let month_raw = (date >> 5) & 0x0F;
    let day_raw = date & 0x1F;

    let year = 1980 + year_offset;

    if year < 1980 || year > 2107 {
        return Err(DosTimestampError::InvalidDate);
    }
    if month_raw < 1 || month_raw > 12 {
        return Err(DosTimestampError::InvalidDate);
    }
    let month = month_raw as u8;
    let max_day = days_in_month(year, month);
    let day_narrowed = day_raw as u8;
    if day_narrowed < 1 || day_narrowed > max_day {
        return Err(DosTimestampError::InvalidDate);
    }
    let day = day_narrowed;

    let hour_raw = (time >> 11) & 0x1F;
    let minute_raw = (time >> 5) & 0x3F;
    let second_raw = time & 0x1F;
    let second = second_raw * 2;

    if hour_raw > 23 {
        return Err(DosTimestampError::InvalidTime);
    }
    if minute_raw > 59 {
        return Err(DosTimestampError::InvalidTime);
    }
    if second > 59 {
        return Err(DosTimestampError::InvalidTime);
    }

    let hour = hour_raw as u8;
    let minute = minute_raw as u8;
    let second = second as u8;

    Ok(DosDateTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
    })
}

pub fn encode_dos(value: &DosDateTime) -> Result<(u16, u16), DosTimestampError> {
    if value.year < 1980 || value.year > 2107 {
        return Err(DosTimestampError::InvalidDate);
    }
    if value.month < 1 || value.month > 12 {
        return Err(DosTimestampError::InvalidDate);
    }
    let max_day = days_in_month(value.year, value.month);
    if value.day < 1 || value.day > max_day {
        return Err(DosTimestampError::InvalidDate);
    }

    if value.hour > 23 {
        return Err(DosTimestampError::InvalidTime);
    }
    if value.minute > 59 {
        return Err(DosTimestampError::InvalidTime);
    }
    if value.second > 59 {
        return Err(DosTimestampError::InvalidTime);
    }

    if value.second % 2 != 0 {
        return Err(DosTimestampError::OddSecond);
    }

    let date_word = ((value.year as u16 - 1980) << 9)
        | ((value.month as u16) << 5)
        | (value.day as u16);

    let time_word = ((value.hour as u16) << 11)
        | ((value.minute as u16) << 5)
        | (value.second as u16 / 2);

    Ok((date_word, time_word))
}