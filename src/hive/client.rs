use serde::Serialize;
use serde_json::Value;


pub struct HiveClient { pub url: String, client: reqwest::Client }

#[derive(Serialize)]
struct HiveRequest { pub jsonrpc: String, pub method: String, pub params: Value, pub id: i64 }


impl HiveClient {
    pub fn new(url: &str) -> Self {
       Self { url: url.to_string(), client: reqwest::Client::new() }
    }

    pub async fn request(&self, method: &str, params: Value) -> Value {
        let req = HiveRequest { jsonrpc: String::from("2.0"), method: method.to_string(), params, id: 1 };
        let json = serde_json::to_string(&req).unwrap();

        let response: &Value = &self.client
            .post(&self.url)
            .body(json)
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        
        response.to_owned()
    }
}
