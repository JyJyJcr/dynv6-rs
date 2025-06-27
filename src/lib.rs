use std::{
    fmt::{Debug, Display, Formatter},
    net::{Ipv4Addr, Ipv6Addr},
};

use reqwest::RequestBuilder;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use typed_id::TypedId;

pub struct AccessToken {
    literal: String,
}
impl AccessToken {
    pub fn new<S: Into<String>>(literal: S) -> Self {
        Self {
            literal: literal.into(),
        }
    }
}
impl Debug for AccessToken {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        f.debug_tuple("AccessToken").finish_non_exhaustive()
    }
}
impl Display for AccessToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", "***MASKED***")
    }
}

// #[derive(PartialEq, Eq)]
// pub struct ZoneID {
//     serial: u64,
// }
// impl Display for ZoneID {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         write!(f, "{}", self.serial)
//     }
// }

// pub struct RecordID {
//     serial: u64,
// }

// impl Display for RecordID {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         write!(f, "{}", self.serial)
//     }
// }

pub type ZoneID = TypedId<u64, Zone>;
pub type RecordID = TypedId<u64, Record>;

#[derive(PartialEq, Eq, Serialize, Deserialize, Debug, Clone)]
pub struct ZoneNode {
    pub id: ZoneID,
    #[serde(flatten)]
    pub zone: Zone,
    #[serde(rename(serialize = "createdAt", deserialize = "createdAt"))]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(rename(serialize = "updatedAt", deserialize = "updatedAt"))]
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(PartialEq, Eq, Serialize, Deserialize, Debug, Clone)]
pub struct Zone {
    pub name: String,
    #[serde(flatten)]
    pub value: ZoneValue,
}
#[derive(PartialEq, Eq, Serialize, Deserialize, Debug, Clone)]
pub struct ZoneValue {
    #[serde(
        deserialize_with = "deserialize_or_none",
        serialize_with = "serialize_or_empty_str"
    )]
    pub ipv4address: Option<Ipv4Addr>,
    #[serde(
        deserialize_with = "deserialize_or_none",
        serialize_with = "serialize_or_empty_str"
    )]
    pub ipv6prefix: Option<Ipv6Addr>,
}

fn deserialize_or_none<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(T::deserialize(de).ok())
}

fn serialize_or_empty_str<S, T>(t: &Option<T>, se: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize,
{
    match t {
        Some(t) => t.serialize(se),
        None => se.serialize_str(""),
    }
}

#[derive(PartialEq, Eq, Serialize, Deserialize, Debug, Clone)]
pub struct RecordNode {
    pub id: RecordID,
    #[serde(rename(serialize = "zoneID", deserialize = "zoneID"))]
    pub zone_id: ZoneID,
    #[serde(flatten)]
    pub record: Record,
}
#[derive(PartialEq, Eq, Serialize, Deserialize, Debug, Hash, Clone)]
pub struct Record {
    pub name: String,
    #[serde(flatten)]
    pub value: RecordValue,
}

#[derive(PartialEq, Eq, Serialize, Deserialize, Debug, Hash, Clone)]
#[allow(non_snake_case)]
#[serde(tag = "type")]
pub enum RecordValue {
    A {
        data: Ipv4Addr,
    },
    AAAA {
        data: Ipv6Addr,
    },
    CNAME {
        data: String,
        //expandedData: String,
    },
    SRV {
        data: String,
        priority: u16,
        weight: u16,
        port: u16,
    },
    TXT {
        data: String,
    },
}

// struct Domain {
//     labels: Vec<String>,
// }
// impl Display for Domain {

// }

#[derive(Debug)]
pub struct Client {
    token: AccessToken,
    client: reqwest::Client,
}
impl Client {
    //new
    pub fn new(token: AccessToken) -> Client {
        Client::new_with_client(token, reqwest::Client::new())
    }
    pub fn new_with_client(token: AccessToken, client: reqwest::Client) -> Client {
        Client { token, client }
    }

    //zone commands
    pub async fn get_zone_list(&self) -> Result<Vec<ZoneNode>, reqwest::Error> {
        let response = self
            .client
            .get("https://dynv6.com/api/v2/zones")
            .dynv6_header(&self.token)
            .send()
            .await?;
        response.json::<Vec<ZoneNode>>().await
    }
    pub async fn add_zone(&self, zone: &Zone) -> Result<ZoneNode, reqwest::Error> {
        let response = self
            .client
            .post(format!("https://dynv6.com/api/v2/zones"))
            .dynv6_header(&self.token)
            .json(zone)
            .send()
            .await?;
        response.json::<ZoneNode>().await
    }
    pub async fn get_zone(&self, zone_id: &ZoneID) -> Result<ZoneNode, reqwest::Error> {
        let response = self
            .client
            .get(format!("https://dynv6.com/api/v2/zones/{}", zone_id))
            .dynv6_header(&self.token)
            .send()
            .await?;
        response.json::<ZoneNode>().await
    }
    pub async fn update_zone(
        &self,
        zone_id: &ZoneID,
        zone_value: &ZoneValue,
    ) -> Result<ZoneNode, reqwest::Error> {
        let response = self
            .client
            .patch(format!("https://dynv6.com/api/v2/zones/{}", zone_id))
            .dynv6_header(&self.token)
            .json(zone_value)
            .send()
            .await?;
        response.json::<ZoneNode>().await
    }
    pub async fn delete_zone(&self, zone_id: &ZoneID) -> Result<(), reqwest::Error> {
        let response = self
            .client
            .delete(format!("https://dynv6.com/api/v2/zones/{}", zone_id))
            .dynv6_header(&self.token)
            .send()
            .await?;
        response.error_for_status()?;
        Ok(())
    }
    pub async fn get_zone_by_name(&self, domain: &str) -> Result<ZoneNode, reqwest::Error> {
        let response = self
            .client
            .get(format!("https://dynv6.com/api/v2/zones/by-name/{}", domain))
            .dynv6_header(&self.token)
            .send()
            .await?;
        response.json::<ZoneNode>().await
    }

    //record commands
    pub async fn get_record_list(
        &self,
        zone_id: &ZoneID,
    ) -> Result<Vec<RecordNode>, reqwest::Error> {
        let response = self
            .client
            .get(format!(
                "https://dynv6.com/api/v2/zones/{}/records",
                zone_id
            ))
            .dynv6_header(&self.token)
            .send()
            .await?;
        response.json::<Vec<RecordNode>>().await
    }
    pub async fn add_record(
        &self,
        zone_id: &ZoneID,
        record: &Record,
    ) -> Result<RecordNode, reqwest::Error> {
        let response = self
            .client
            .post(format!(
                "https://dynv6.com/api/v2/zones/{}/records",
                zone_id
            ))
            .dynv6_header(&self.token)
            .json(record)
            .send()
            .await?;
        response.json::<RecordNode>().await
    }
    pub async fn get_record(
        &self,
        zone_id: &ZoneID,
        record_id: &RecordID,
    ) -> Result<RecordNode, reqwest::Error> {
        let response = self
            .client
            .get(format!(
                "https://dynv6.com/api/v2/zones/{}/records/{}",
                zone_id, record_id,
            ))
            .dynv6_header(&self.token)
            .send()
            .await?;
        response.json::<RecordNode>().await
    }
    pub async fn update_record(
        &self,
        zone_id: &ZoneID,
        record_id: &RecordID,
        record: &Record,
    ) -> Result<RecordNode, reqwest::Error> {
        let response = self
            .client
            .patch(format!(
                "https://dynv6.com/api/v2/zones/{}/records/{}",
                zone_id, record_id,
            ))
            .dynv6_header(&self.token)
            .json(record)
            .send()
            .await?;
        response.json::<RecordNode>().await
    }

    pub async fn delete_record(
        &self,
        zone_id: &ZoneID,
        record_id: &RecordID,
    ) -> Result<(), reqwest::Error> {
        let response = self
            .client
            .delete(format!(
                "https://dynv6.com/api/v2/zones/{}/records/{}",
                zone_id, record_id
            ))
            .dynv6_header(&self.token)
            .send()
            .await?;
        response.error_for_status()?;
        Ok(())
        //response.json::<RecordNode>().await
    }
}

trait Dynv6QueryBuilder: Sized {
    fn dynv6_header(self, token: &AccessToken) -> Self;
}

impl Dynv6QueryBuilder for RequestBuilder {
    fn dynv6_header(self, token: &AccessToken) -> Self {
        self.header(
            reqwest::header::AUTHORIZATION,
            String::from("Bearer ") + &token.literal,
        )
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
    }
}

#[cfg(test)]
mod tests {

    //use reqwest::StatusCode;
    use serde::Deserialize;

    use super::{AccessToken, Record, RecordValue, Zone, ZoneValue};

    use super::Client;

    #[derive(Deserialize)]
    struct SecretConfig {
        token: String,
        const_zone: String,
        mut_zone: String,
        tmp_zone_suffix: String,
    }
    fn config() -> SecretConfig {
        serde_json::from_str(include_str!(".secret.json")).unwrap()
    }

    fn signature() -> u32 {
        let mut buf: [u8; 4] = [0; 4];
        getrandom::getrandom(&mut buf).unwrap();
        u32::from_be_bytes(buf)
    }

    fn create_client(token: String) -> Client {
        let token = AccessToken { literal: token };
        Client::new(token)
    }

    #[test]
    fn hide_token() {
        let token = AccessToken {
            literal: String::from("this must not be shown by Display impl"),
        };
        assert_eq!(format!("{}", token), String::from("***MASKED***"));
        assert_eq!(format!("{:?}", token), String::from("AccessToken(..)"));
    }

    #[test]
    fn zone_value_serde() {
        let x: ZoneValue = serde_json::from_str(
            //r#"{"ipv4address":"192.0.2.1","ipv6prefix":"2001:db8::1"}"#,
            r#"{"ipv4address":"192.0.2.1","ipv6prefix":""}"#,
        )
        .unwrap();
        assert_eq!(
            x,
            ZoneValue {
                ipv4address: Some("192.0.2.1".parse().unwrap()),
                ipv6prefix: None,
            }
        );
        assert_eq!(
            serde_json::to_string(&x).unwrap(),
            r#"{"ipv4address":"192.0.2.1","ipv6prefix":""}"#
        );
    }

    #[tokio::test]
    async fn zone_passive() {
        let config = config();
        let client = create_client(config.token);
        let zone_nodes = client.get_zone_list().await.unwrap();
        let found_zone_node = zone_nodes
            .into_iter()
            .find(|z| z.zone.name == config.const_zone)
            .unwrap();
        println!("{:?}", found_zone_node);
        let zone_node_by_id = client.get_zone(&found_zone_node.id).await.unwrap();
        let zone_node_by_name = client.get_zone_by_name(&config.const_zone).await.unwrap();
        assert_eq!(found_zone_node, zone_node_by_name);
        assert_eq!(found_zone_node, zone_node_by_id);
    }

    #[tokio::test]
    async fn zone_active() {
        let config = config();
        let client = create_client(config.token);
        let tmp_zone_name = format!("{:x}{}", signature(), config.tmp_zone_suffix);
        let new_zone = client
            .add_zone(&Zone {
                name: tmp_zone_name,
                value: ZoneValue {
                    ipv4address: None,
                    ipv6prefix: None,
                },
            })
            .await
            .unwrap();
        assert_eq!(
            new_zone.zone.value,
            ZoneValue {
                ipv4address: None,
                ipv6prefix: None,
            }
        );

        let new_zone = client
            .update_zone(
                &new_zone.id,
                &ZoneValue {
                    ipv4address: Some("192.0.2.1".parse().unwrap()),
                    ipv6prefix: Some("2001:db8::1".parse().unwrap()),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            new_zone.zone.value,
            ZoneValue {
                ipv4address: Some("192.0.2.1".parse().unwrap()),
                ipv6prefix: Some("2001:db8::1".parse().unwrap()),
            }
        );

        println!("{:?}", new_zone);
        client.delete_zone(&new_zone.id).await.unwrap();
        //assert_eq!(zone, zone_by_name);

        //let a = records;
    }

    #[tokio::test]
    async fn record_passive() {
        let config = config();
        let client = create_client(config.token);
        let zone = client.get_zone_by_name(&config.const_zone).await.unwrap();
        //println!("{:?}", zone);

        let zone_id = zone.id;

        let record_nodes = client.get_record_list(&zone_id).await.unwrap();
        for record_node in record_nodes.iter() {
            println!("record: {:?}", record_node);
        }
        let first_record_node = &record_nodes[0];
        let record_node_by_id = client
            .get_record(&zone_id, &first_record_node.id)
            .await
            .unwrap();
        assert_eq!(*first_record_node, record_node_by_id);
        //let a = records;
    }

    #[tokio::test]
    async fn record_active() {
        let config = config();
        let client = create_client(config.token);
        let zone = client.get_zone_by_name(&config.mut_zone).await.unwrap();

        let zone_id = zone.id;

        let sig = signature();
        let txt_rec = Record {
            name: format!("{:x}-test", sig),
            value: RecordValue::CNAME {
                data: String::from("mumblemumble"),
                //expandedData: todo!(),
            },
        };

        let txt_rec_node = client.add_record(&zone_id, &txt_rec).await.unwrap();
        println!("{:?}", txt_rec_node);
        assert_eq!(txt_rec, txt_rec_node.record);

        let record_id = txt_rec_node.id;

        let new_txt_rec = Record {
            name: format!("{:x}-upc", sig),
            value: RecordValue::CNAME {
                data: String::from("もやしっこ"),
                //expandedData: todo!(),
            },
        };

        let new_txt_rec_node = client
            .update_record(&zone_id, &record_id, &new_txt_rec)
            .await
            .unwrap();
        println!("{:?}", new_txt_rec_node);
        assert_eq!(record_id, new_txt_rec_node.id);
        assert_eq!(new_txt_rec, new_txt_rec_node.record);

        client.delete_record(&zone_id, &record_id).await.unwrap();
        //let a = records;
    }
}
