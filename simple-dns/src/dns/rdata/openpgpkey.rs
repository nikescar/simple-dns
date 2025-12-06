use crate::{bytes_buffer::BytesBuffer, dns::WireFormat, lib::Cow, lib::Write};

use super::RR;

/// An OPENPGPKEY record see [rfc7929](https://www.rfc-editor.org/rfc/rfc7929)
/// Contains an OpenPGP transferable public key
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct OPENPGPKEY<'a> {
    /// The OpenPGP transferable public key in binary format
    pub public_key: Cow<'a, [u8]>,
}

impl RR for OPENPGPKEY<'_> {
    const TYPE_CODE: u16 = 61;
}

impl<'a> WireFormat<'a> for OPENPGPKEY<'a> {
    const MINIMUM_LEN: usize = 0;

    fn parse(data: &mut BytesBuffer<'a>) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let public_key = Cow::Borrowed(data.get_remaining());

        Ok(Self { public_key })
    }

    fn write_to<T: Write>(&self, out: &mut T) -> crate::Result<()> {
        out.write_all(&self.public_key)?;

        Ok(())
    }

    fn len(&self) -> usize {
        self.public_key.len()
    }
}

impl OPENPGPKEY<'_> {
    /// Transforms the inner data into its owned type
    pub fn into_owned<'b>(self) -> OPENPGPKEY<'b> {
        OPENPGPKEY {
            public_key: Cow::Owned(self.public_key.into_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lib::{vec, Vec};

    #[test]
    fn parse_and_write_openpgpkey() {
        let public_key = vec![1, 2, 3, 4, 5];
        let rdata = OPENPGPKEY {
            public_key: Cow::Owned(public_key),
        };
        let mut writer = Vec::new();
        rdata.write_to(&mut writer).unwrap();
        let rdata = OPENPGPKEY::parse(&mut (&writer[..]).into()).unwrap();
        assert_eq!(&*rdata.public_key, &[1, 2, 3, 4, 5]);
    }
}
