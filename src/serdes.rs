use bulletproofs::{group::Group, BulletproofCurveArithmetic};
use core::marker::PhantomData;
use std::fmt::{self, Formatter};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeTuple;

pub struct CurveScalar<C: BulletproofCurveArithmetic> {
    _marker: PhantomData<C>,
}

impl<C: BulletproofCurveArithmetic> CurveScalar<C> {
    pub fn serialize<S: Serializer>(scalar: &C::Scalar, s: S) -> Result<S::Ok, S::Error> {
        let bytes = C::serialize_scalar(scalar);
        if s.is_human_readable() {
            data_encoding::BASE64.encode(&bytes).serialize(s)
        } else {
            let mut tupler = s.serialize_tuple(bytes.len())?;
            for b in bytes {
                tupler.serialize_element(&b)?;
            }
            tupler.end()
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<C::Scalar, D::Error> {
        if d.is_human_readable() {
            let value = String::deserialize(d)?;
            let bytes = data_encoding::BASE64
                .decode(value.as_bytes())
                .map_err(|_| serde::de::Error::custom("invalid base64"))?;
            C::deserialize_scalar(&bytes).map_err(|_| serde::de::Error::custom("invalid scalar"))
        } else {
            struct ScalarVisitor<C: BulletproofCurveArithmetic>(PhantomData<C>);
            impl<'de, C: BulletproofCurveArithmetic> Visitor<'de> for ScalarVisitor<C> {
                type Value = C::Scalar;

                fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                    write!(f, "a sequence of bytes")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error> where A: SeqAccess<'de> {
                    let mut bytes = Vec::<u8>::with_capacity(C::SCALAR_BYTES);
                    for _ in 0..C::SCALAR_BYTES {
                        bytes.push(seq.next_element()?.ok_or_else(|| serde::de::Error::custom("invalid scalar"))?);
                    }
                    C::deserialize_scalar(&bytes).map_err(|_| serde::de::Error::custom("invalid scalar"))
                }
            }
            d.deserialize_tuple(C::SCALAR_BYTES, ScalarVisitor(PhantomData::<C>))
        }
    }
}

pub struct CurvePoint<C: BulletproofCurveArithmetic> {
    _marker: PhantomData<C>,
}

impl<C: BulletproofCurveArithmetic> CurvePoint<C> {
    pub fn serialize<S: Serializer>(scalar: &C::Point, s: S) -> Result<S::Ok, S::Error> {
        let bytes = C::serialize_point(scalar);
        if s.is_human_readable() {
            data_encoding::BASE64.encode(&bytes).serialize(s)
        } else {
            let mut tupler = s.serialize_tuple(bytes.len())?;
            for b in bytes {
                tupler.serialize_element(&b)?;
            }
            tupler.end()
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<C::Point, D::Error> {
        if d.is_human_readable() {
            let value = String::deserialize(d)?;
            let bytes = data_encoding::BASE64
                .decode(value.as_bytes())
                .map_err(|_| serde::de::Error::custom("invalid base64"))?;
            C::deserialize_point(&bytes).map_err(|_| serde::de::Error::custom("invalid point"))
        } else {
            struct PointVisitor<C: BulletproofCurveArithmetic>(PhantomData<C>);
            impl<'de, C: BulletproofCurveArithmetic> Visitor<'de> for PointVisitor<C> {
                type Value = C::Point;

                fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                    write!(f, "a sequence of bytes")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error> where A: SeqAccess<'de> {
                    let mut bytes = Vec::<u8>::with_capacity(C::POINT_BYTES);
                    for _ in 0..C::POINT_BYTES {
                        bytes.push(seq.next_element()?.ok_or_else(|| serde::de::Error::custom("invalid point"))?);
                    }
                    C::deserialize_point(&bytes).map_err(|_| serde::de::Error::custom("invalid point"))
                }
            }
            d.deserialize_tuple(C::POINT_BYTES, PointVisitor(PhantomData::<C>))
        }
    }
}

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
            let mut tupler = s.serialize_tuple(bytes.len())?;
            for b in bytes {
                tupler.serialize_element(&b)?;
            }
            tupler.end()
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
            Ok(points)
        } else {
            struct PointArrayVisitor<C: BulletproofCurveArithmetic>(PhantomData<C>);

            impl<'de, C: BulletproofCurveArithmetic> Visitor<'de> for PointArrayVisitor<C> {
                type Value = [C::Point; 32];

                fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                    write!(f, "a sequence of bytes for 32 points")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error> where A: SeqAccess<'de> {
                    let mut points = [C::Point::identity(); 32];
                    let mut bytes = vec![0u8; C::POINT_BYTES];
                    for pt in points.iter_mut() {
                        for b in bytes.iter_mut() {
                            *b = seq.next_element()?.ok_or_else(|| serde::de::Error::custom("invalid point"))?;
                        }
                        *pt = C::deserialize_point(&bytes).map_err(|_| serde::de::Error::custom("invalid point"))?;
                    }
                    Ok(points)
                }
            }
            d.deserialize_tuple(32 * C::POINT_BYTES, PointArrayVisitor(PhantomData::<C>))
        }
    }
}
