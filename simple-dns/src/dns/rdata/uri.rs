use crate::{bytes_buffer::BytesBuffer, dns::WireFormat, lib::Cow, lib::Write};

use super::RR;

/// A URI record see [rfc7553](https://www.rfc-editor.org/rfc/rfc7553)
/// Maps a domain name to a Uniform Resource Identifier
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct URI<'a> {
    /// Priority of this target URI, lower values are preferred
    pub priority: u16,
    /// Weight for server selection, higher values have higher probability
    pub weight: u16,
    /// The URI as a sequence of octets
    pub target: Cow<'a, [u8]>,
}

impl RR for URI<'_> {
    const TYPE_CODE: u16 = 256;
}

impl<'a> WireFormat<'a> for URI<'a> {
    const MINIMUM_LEN: usize = 4;

    fn parse(data: &mut BytesBuffer<'a>) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let priority = data.get_u16()?;
        let weight = data.get_u16()?;
        let target = Cow::Borrowed(data.get_remaining());

        Ok(Self {
            priority,
            weight,
            target,
        })
    }

    fn write_to<T: Write>(&self, out: &mut T) -> crate::Result<()> {
        out.write_all(&self.priority.to_be_bytes())?;
        out.write_all(&self.weight.to_be_bytes())?;
        out.write_all(&self.target)?;

        Ok(())
    }

    fn len(&self) -> usize {
        self.target.len() + Self::MINIMUM_LEN
    }
}

impl URI<'_> {
    /// Transforms the inner data into its owned type
    pub fn into_owned<'b>(self) -> URI<'b> {
        URI {
            priority: self.priority,
            weight: self.weight,
            target: Cow::Owned(self.target.into_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lib::{vec, Vec};

    #[test]
    fn parse_and_write_uri() {
        let priority = 10u16;
        let weight = 1u16;
        let target = b"https://example.com/path".to_vec();
        let rdata = URI {
            priority,
            weight,
            target: Cow::Owned(target.clone()),
        };
        let mut writer = Vec::new();
        rdata.write_to(&mut writer).unwrap();
        let rdata = URI::parse(&mut (&writer[..]).into()).unwrap();
        assert_eq!(rdata.priority, priority);
        assert_eq!(rdata.weight, weight);
        assert_eq!(&*rdata.target, &target[..]);
    }
}
