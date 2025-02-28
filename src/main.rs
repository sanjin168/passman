use clap::{Parser, Subcommand};
use prettytable::{Table, Row, Cell};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose};

// 主程序参数结构
#[derive(Parser)]
#[command(name = "passman")]
#[command(about = "一个简单的密码管理命令行工具", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

// 子命令
#[derive(Subcommand)]
enum Commands {
    /// 添加新账号
    Add {
        /// 用户名
        #[arg(short, long)]
        username: String,
        
        /// 密码
        #[arg(short, long)]
        password: String,
        
        /// 备注信息（包含网站或应用信息）
        #[arg(short, long)]
        notes: String,
    },
    
    /// 删除账号
    Delete {
        /// 用户名
        #[arg(short, long)]
        username: String,
    },
    
    /// 更新账号信息
    Update {
        /// 用户名
        #[arg(short, long)]
        username: String,
        
        /// 新密码（可选）
        #[arg(short, long)]
        password: Option<String>,
        
        /// 新备注信息（可选）
        #[arg(short, long)]
        notes: Option<String>,
    },
    
    /// 查看所有账号信息
    List,
    
    /// 查看特定账号信息
    Get {
        /// 用户名
        #[arg(short, long)]
        username: String,
    },
}

// 账号信息结构
#[derive(Serialize, Deserialize, Clone)]
struct Account {
    password: String,
    notes: String,
}

// 密码库结构
#[derive(Serialize, Deserialize)]
struct PasswordStore {
    // 使用随机生成的初始化向量(IV)
    iv: String,
    // 加密后的数据
    encrypted_data: String,
}

// 存储实际账号数据的结构
type AccountStore = HashMap<String, Account>;

// 数据文件路径
const DATA_FILE: &str = ".passman_data.json";
// 初始化向量长度
const NONCE_LENGTH: usize = 12;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    // 请求主密钥
    let master_key = read_password("请输入主密钥: ")?;
    let key = derive_key(&master_key);
    
    // 根据子命令执行相应操作
    match &cli.command {
        Commands::Add { username, password, notes } => {
            add_account(&key, username, password, notes)?;
            println!("账号添加成功: {}", username);
        }
        
        Commands::Delete { username } => {
            delete_account(&key, username)?;
            println!("账号删除成功: {}", username);
        }
        
        Commands::Update { username, password, notes } => {
            update_account(&key, username, password, notes)?;
            println!("账号更新成功: {}", username);
        }
        
        Commands::List => {
            list_accounts(&key)?;
        }
        
        Commands::Get { username } => {
            get_account(&key, username)?;
        }
    }
    
    Ok(())
}

// 从主密钥派生加密密钥
fn derive_key(master_key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(master_key.as_bytes());
    let result = hasher.finalize();
    
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

// 读取密码（不回显）
fn read_password(prompt: &str) -> Result<String, io::Error> {
    print!("{}", prompt);
    io::stdout().flush()?;
    
    let password = rpassword::read_password()?;
    Ok(password)
}

// 自定义错误类型以包装 aes_gcm::Error
#[derive(Debug)]
enum AppError {
    IoError(io::Error),
    SerdeError(serde_json::Error),
    Base64Error(base64::DecodeError),
    AesError(String),
    OtherError(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::IoError(e) => write!(f, "IO错误: {}", e),
            AppError::SerdeError(e) => write!(f, "序列化错误: {}", e),
            AppError::Base64Error(e) => write!(f, "Base64解码错误: {}", e),
            AppError::AesError(s) => write!(f, "加密/解密错误: {}", s),
            AppError::OtherError(s) => write!(f, "其他错误: {}", s),
        }
    }
}

impl std::error::Error for AppError {}

impl From<io::Error> for AppError {
    fn from(err: io::Error) -> Self {
        AppError::IoError(err)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::SerdeError(err)
    }
}

impl From<base64::DecodeError> for AppError {
    fn from(err: base64::DecodeError) -> Self {
        AppError::Base64Error(err)
    }
}

impl From<aes_gcm::Error> for AppError {
    fn from(_: aes_gcm::Error) -> Self {
        AppError::AesError("加密/解密操作失败".to_string())
    }
}

impl From<&str> for AppError {
    fn from(s: &str) -> Self {
        AppError::OtherError(s.to_string())
    }
}

impl From<String> for AppError {
    fn from(s: String) -> Self {
        AppError::OtherError(s)
    }
}

// 加载账号存储
fn load_accounts(key: &[u8; 32]) -> Result<AccountStore, AppError> {
    if !Path::new(DATA_FILE).exists() {
        return Ok(AccountStore::new());
    }
    
    let file_content = fs::read_to_string(DATA_FILE)?;
    let store: PasswordStore = serde_json::from_str(&file_content)?;
    
    // 解码IV
    let iv = general_purpose::STANDARD.decode(&store.iv)?;
    let nonce = Nonce::from_slice(&iv);
    
    // 解码加密数据
    let encrypted_data = general_purpose::STANDARD.decode(&store.encrypted_data)?;
    
    // 解密
    let cipher = Aes256Gcm::new(key.into());
    let decrypted_data = cipher.decrypt(nonce, encrypted_data.as_ref())?;
    
    // 解析账号数据
    let accounts: AccountStore = serde_json::from_slice(&decrypted_data)?;
    
    Ok(accounts)
}

// 保存账号存储
fn save_accounts(key: &[u8; 32], accounts: &AccountStore) -> Result<(), AppError> {
    // 序列化账号数据
    let data = serde_json::to_vec(accounts)?;
    
    // 生成随机IV
    let iv = rand::random::<[u8; NONCE_LENGTH]>();
    let nonce = Nonce::from_slice(&iv);
    
    // 加密
    let cipher = Aes256Gcm::new(key.into());
    let encrypted_data = cipher.encrypt(nonce, data.as_ref())?;
    
    // 创建密码库结构
    let store = PasswordStore {
        iv: general_purpose::STANDARD.encode(iv),
        encrypted_data: general_purpose::STANDARD.encode(encrypted_data),
    };
    
    // 保存到文件
    let json = serde_json::to_string(&store)?;
    fs::write(DATA_FILE, json)?;
    
    Ok(())
}

// 添加账号
fn add_account(key: &[u8; 32], username: &str, password: &str, notes: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut accounts = load_accounts(key)?;
    
    if accounts.contains_key(username) {
        return Err(Box::new(AppError::from("账号已存在")));
    }
    
    accounts.insert(username.to_string(), Account {
        password: password.to_string(),
        notes: notes.to_string(),
    });
    
    save_accounts(key, &accounts)?;
    
    Ok(())
}

// 删除账号
fn delete_account(key: &[u8; 32], username: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut accounts = load_accounts(key)?;
    
    if !accounts.contains_key(username) {
        return Err(Box::new(AppError::from("账号不存在")));
    }
    
    accounts.remove(username);
    save_accounts(key, &accounts)?;
    
    Ok(())
}

// 更新账号
fn update_account(
    key: &[u8; 32],
    username: &str,
    password: &Option<String>,
    notes: &Option<String>
) -> Result<(), Box<dyn std::error::Error>> {
    let mut accounts = load_accounts(key)?;
    
    if !accounts.contains_key(username) {
        return Err(Box::new(AppError::from("账号不存在")));
    }
    
    let account = accounts.get_mut(username).unwrap();
    
    if let Some(password) = password {
        account.password = password.clone();
    }
    
    if let Some(notes) = notes {
        account.notes = notes.clone();
    }
    
    save_accounts(key, &accounts)?;
    
    Ok(())
}

// 列出所有账号
fn list_accounts(key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    let accounts = load_accounts(key)?;
    
    if accounts.is_empty() {
        println!("无存储的账号");
        return Ok(());
    }
    
    let mut table = Table::new();
    table.add_row(Row::new(vec![
        Cell::new("用户名"),
        Cell::new("密码"),
        Cell::new("备注"),
    ]));
    
    for (username, account) in accounts {
        table.add_row(Row::new(vec![
            Cell::new(&username),
            Cell::new(&account.password),
            Cell::new(&account.notes),
        ]));
    }
    
    table.printstd();
    
    Ok(())
}

// 获取特定账号
fn get_account(key: &[u8; 32], username: &str) -> Result<(), Box<dyn std::error::Error>> {
    let accounts = load_accounts(key)?;
    
    if !accounts.contains_key(username) {
        return Err(Box::new(AppError::from("账号不存在")));
    }
    
    let account = accounts.get(username).unwrap();
    
    let mut table = Table::new();
    table.add_row(Row::new(vec![
        Cell::new("用户名"),
        Cell::new("密码"),
        Cell::new("备注"),
    ]));
    
    table.add_row(Row::new(vec![
        Cell::new(username),
        Cell::new(&account.password),
        Cell::new(&account.notes),
    ]));
    
    table.printstd();
    
    Ok(())
}
