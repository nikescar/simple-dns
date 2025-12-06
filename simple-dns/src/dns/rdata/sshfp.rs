use crate::{bytes_buffer::BytesBuffer, dns::WireFormat, lib::Cow, lib::Write};

use super::RR;

/// An SSHFP record see [rfc4255](https://datatracker.ietf.org/doc/html/rfc4255)
/// Contains SSH public host key fingerprints
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SSHFP<'a> {
    /// Algorithm number
    pub algorithm: u8,
    /// Fingerprint type
    pub fp_type: u8,
    /// Fingerprint
    pub fingerprint: Cow<'a, [u8]>,
}

impl RR for SSHFP<'_> {
    const TYPE_CODE: u16 = 44;
}

impl<'a> WireFormat<'a> for SSHFP<'a> {
    const MINIMUM_LEN: usize = 2;

    fn parse(data: &mut BytesBuffer<'a>) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let algorithm = data.get_u8()?;
        let fp_type = data.get_u8()?;
        let fingerprint = Cow::Borrowed(data.get_remaining());

        Ok(Self {
            algorithm,
            fp_type,
            fingerprint,
        })
    }

    fn write_to<T: Write>(&self, out: &mut T) -> crate::Result<()> {
        out.write_all(&[self.algorithm])?;
        out.write_all(&[self.fp_type])?;
        out.write_all(&self.fingerprint)?;

        Ok(())
    }

    fn len(&self) -> usize {
        self.fingerprint.len() + Self::MINIMUM_LEN
    }
}

impl SSHFP<'_> {
    /// Transforms the inner data into its owned type
    pub fn into_owned<'b>(self) -> SSHFP<'b> {
        SSHFP {
            algorithm: self.algorithm,
            fp_type: self.fp_type,
            fingerprint: Cow::Owned(self.fingerprint.into_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lib::{vec, Vec};

    #[test]
    fn parse_and_write_sshfp() {
        let fingerprint = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let rdata = SSHFP {
            algorithm: 1,
            fp_type: 1,
            fingerprint: Cow::Owned(fingerprint.clone()),
        };
        let mut writer = Vec::new();
        rdata.write_to(&mut writer).unwrap();
        let rdata = SSHFP::parse(&mut (&writer[..]).into()).unwrap();
        assert_eq!(rdata.algorithm, 1);
        assert_eq!(rdata.fp_type, 1);
        assert_eq!(&*rdata.fingerprint, &fingerprint[..]);
    }
}
