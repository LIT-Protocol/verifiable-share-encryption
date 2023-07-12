use bulletproofs::{group::Group, BulletproofCurveArithmetic};
use core::marker::PhantomData;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub struct PointArray<C: BulletproofCurveArithmetic> {
    _marker: PhantomData<C>,
}

impl<C: BulletproofCurveArithmetic> PointArray<C> {
    pub fn serialize<S: Serializer>(points: &[C::Point; 32], s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            let mut values = Vec::with_capacity(32);
            for point in points.iter() {
                let bytes = C::serialize_point(point);
                values.push(data_encoding::BASE64.encode(&bytes));
            }
            values.serialize(s)
        } else {
            let mut bytes = Vec::with_capacity(32 * C::POINT_BYTES);
            for point in points.iter() {
                bytes.append(&mut C::serialize_point(point));
            }

            s.serialize_bytes(&bytes)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[C::Point; 32], D::Error> {
        let mut points = [C::Point::identity(); 32];
        if d.is_human_readable() {
            let values = Vec::<String>::deserialize(d)?;
            if values.len() != 32 {
                return Err(serde::de::Error::custom("invalid point array length"));
            }
            for (i, value) in values.iter().enumerate() {
                let bytes = data_encoding::BASE64
                    .decode(value.as_bytes())
                    .map_err(|_| serde::de::Error::custom("invalid base64"))?;
                if bytes.len() != C::POINT_BYTES {
                    return Err(serde::de::Error::custom("invalid point length"));
                }
                points[i] = C::deserialize_point(&bytes[..C::POINT_BYTES])
                    .map_err(|_| serde::de::Error::custom("invalid point"))?;
            }
        } else {
            let bytes = Vec::<u8>::deserialize(d)?;
            if bytes.len() != 32 * C::POINT_BYTES {
                return Err(serde::de::Error::custom("invalid point array length"));
            }
            let mut pos = &bytes[..C::POINT_BYTES];
            for pt in points.iter_mut() {
                *pt = C::deserialize_point(&pos[..C::POINT_BYTES])
                    .map_err(|_| serde::de::Error::custom("invalid point"))?;
                pos = &pos[C::POINT_BYTES..];
            }
        }
        Ok(points)
    }
}
