use clap::Parser;
use regex::Regex;
use std::fs::File;
use std::io::Write;
use serde_json::Value;

#[derive(Parser)]
#[command(version)]
struct Args {
	/// Target domain
	#[arg(short, long)]
	domain: String,

	/// Save results in a file
	#[arg(short, long)]
	output: Option<String>
}

trait Source {
	fn search(&self, found_subdomains: &mut Vec<String>, domain: &str);
}

struct CrtSh {}

impl Source for CrtSh {
	fn search(&self, found_subdomains: &mut Vec<String>, domain: &str) {
		let url = format!("https://crt.sh/?q={}&exclude=expired&output=json", domain);

		let response = reqwest::blocking::get(url)
			.unwrap();

		let data: Value = response.json()
			.unwrap();

		let certificates = data.as_array()
			.unwrap();

		let pattern = format!("^[0-9a-z.-]+.*{}$", domain);

		let matcher = Regex::new(&pattern)
			.unwrap();

		for certificate in certificates {
			let common_name = certificate.get("common_name")
				.unwrap()
					.as_str()
						.unwrap()
							.to_string();

			if matcher.is_match(&common_name) && !found_subdomains.contains(&common_name) {
				found_subdomains.push(common_name);
			}

			let name_value = certificate.get("name_value")
				.unwrap()
					.as_str()
						.unwrap();

			let subdomains = name_value.lines();

			for subdomain in subdomains {
				let found_subdomain = subdomain.to_string();

				if matcher.is_match(&found_subdomain) && !found_subdomains.contains(&found_subdomain) {
					found_subdomains.push(found_subdomain);
				}
			}
		}
	}
}

struct AnubisDB {}

impl Source for AnubisDB {
	fn search(&self, found_subdomains: &mut Vec<String>, domain: &str) {
		let url = format!("https://anubisdb.com/anubis/subdomains/{}", domain);

		let response = reqwest::blocking::get(url)
			.unwrap();

		let data: Value = response.json()
			.unwrap();

		let subdomains = data.as_array()
			.unwrap();

		for subdomain in subdomains {
			let found_subdomain = subdomain.as_str()
				.unwrap()
					.to_string();

			if found_subdomain.ends_with(domain) && !found_subdomains.contains(&found_subdomain) {
				found_subdomains.push(found_subdomain);
			}
		}
	}
}

struct HackerTarget {}

impl Source for HackerTarget {
	fn search(&self, found_subdomains: &mut Vec<String>, domain: &str) {
		let url = format!("https://api.hackertarget.com/hostsearch/?q={}", domain);

		let response = reqwest::blocking::get(url)
			.unwrap();

		let body = response.text()
			.unwrap();

		let lines = body.lines();

		let pattern = format!("^[0-9a-z.-]+.*{}$", domain);

		let matcher = Regex::new(&pattern)
			.unwrap();

		for line in lines {
			let found_subdomain = line.split(',')
				.nth(0)
					.unwrap()
						.to_string();

			if matcher.is_match(&found_subdomain) && !found_subdomains.contains(&found_subdomain) {
				found_subdomains.push(found_subdomain);
			}
		}
	}
}

fn save_results(found_subdomains: &mut Vec<String>, filename: String) {
	let mut file = File::create(filename)
		.unwrap();

	for found_subdomain in found_subdomains {
		writeln!(file, "{}", found_subdomain)
			.unwrap();
	}
}

fn main() {
	let args = Args::parse();

	let mut found_subdomains: Vec<String> = Vec::new();

	let crt_sh = CrtSh {};

	crt_sh.search(&mut found_subdomains, &args.domain);

	let anubis_db = AnubisDB {};

	anubis_db.search(&mut found_subdomains, &args.domain);

	let hacker_target = HackerTarget {};

	hacker_target.search(&mut found_subdomains, &args.domain);

	found_subdomains.sort();

	for found_subdomain in &found_subdomains {
		println!("{found_subdomain}");
	}

	if let Some(filename) = args.output {
		save_results(&mut found_subdomains, filename);
	}
}