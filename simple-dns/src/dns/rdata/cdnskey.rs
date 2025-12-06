use crate::{bytes_buffer::BytesBuffer, dns::WireFormat, lib::Cow, lib::Write};

use super::RR;

/// A CDNSKEY (Child DNSKEY) record see [rfc7344](https://www.rfc-editor.org/rfc/rfc7344)
/// Has the same format as DNSKEY but used for automated DNSSEC delegation updates
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct CDNSKEY<'a> {
    /// The flags field contains various flags that describe the key's properties
    pub flags: u16,
    /// The protocol field must be set to 3 per RFC4034
    pub protocol: u8,
    /// The algorithm field identifies the public key's cryptographic algorithm
    pub algorithm: u8,
    /// The public key field contains the cryptographic key material in base64 format
    pub public_key: Cow<'a, [u8]>,
}

impl RR for CDNSKEY<'_> {
    const TYPE_CODE: u16 = 60;
}

impl<'a> WireFormat<'a> for CDNSKEY<'a> {
    const MINIMUM_LEN: usize = 4;

    fn parse(data: &mut BytesBuffer<'a>) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let flags = data.get_u16()?;
        let protocol = data.get_u8()?;
        let algorithm = data.get_u8()?;
        let public_key = Cow::Borrowed(data.get_remaining());

        Ok(Self {
            flags,
            protocol,
            algorithm,
            public_key,
        })
    }

    fn write_to<T: Write>(&self, out: &mut T) -> crate::Result<()> {
        out.write_all(&self.flags.to_be_bytes())?;
        out.write_all(&[self.protocol])?;
        out.write_all(&[self.algorithm])?;
        out.write_all(&self.public_key)?;

        Ok(())
    }

    fn len(&self) -> usize {
        self.public_key.len() + Self::MINIMUM_LEN
    }
}

impl CDNSKEY<'_> {
    /// Transforms the inner data into its owned type
    pub fn into_owned<'b>(self) -> CDNSKEY<'b> {
        CDNSKEY {
            flags: self.flags,
            protocol: self.protocol,
            algorithm: self.algorithm,
            public_key: Cow::Owned(self.public_key.into_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lib::{vec, Vec};

    #[test]
    fn parse_and_write_cdnskey() {
        let flags = 257u16; // KSK flag
        let protocol = 3u8;
        let algorithm = 8u8;
        let public_key = vec![1, 2, 3, 4, 5];
        let rdata = CDNSKEY {
            flags,
            protocol,
            algorithm,
            public_key: Cow::Owned(public_key),
        };
        let mut writer = Vec::new();
        rdata.write_to(&mut writer).unwrap();
        let rdata = CDNSKEY::parse(&mut (&writer[..]).into()).unwrap();
        assert_eq!(rdata.flags, flags);
        assert_eq!(rdata.protocol, protocol);
        assert_eq!(rdata.algorithm, algorithm);
        assert_eq!(&*rdata.public_key, &[1, 2, 3, 4, 5]);
    }
}
