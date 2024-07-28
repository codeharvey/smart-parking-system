#[macro_use]
extern crate serde;
use candid::{Decode, Encode};
use ic_cdk::api::time;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{BoundedStorable, Cell, DefaultMemoryImpl, StableBTreeMap, Storable};
use regex::Regex;
use std::fmt;
use std::{borrow::Cow, cell::RefCell};

type Memory = VirtualMemory<DefaultMemoryImpl>;
type IdCell = Cell<u64, Memory>;

// Roles Enumeration
#[derive(
    candid::CandidType, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Default, Debug,
)]
enum UserRole {
    #[default]
    User,
    Admin,
}

// Parking Slot Status enumeration
#[derive(
    candid::CandidType, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Default, Debug,
)]
enum ParkingSlotStatus {
    #[default]
    Available,
    Occupied,
}

// ParkingSpot struct
#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct ParkingSpot {
    id: u64,
    admin_id: u64,
    location: String,
    status: ParkingSlotStatus,
    price_per_hour: f64,
    number_of_spots: u64,
    created_at: u64,
}

// User struct
#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct User {
    id: u64,
    username: String,
    password: String,
    role: UserRole,
    email: String,
    phone_number: String,
    first_name: String,
    last_name: String,
    balance: f64,
    created_at: u64,
}

// Reservation struct
#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Reservation {
    id: u64,
    user_id: u64,
    spot_id: u64,
    reserved_at: u64,
    duration_hours: u64,
    status: String, // "reserved" or "completed"
    amount_payable: f64,
    created_at: u64,
}

// Payment struct
#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Payment {
    id: u64,
    reservation_id: u64,
    amount: f64,
    status: String, // "pending" or "completed"
    created_at: u64,
}

// Transaction struct for logging
#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Transaction {
    user_id: u64,
    amount: f64,
    fee: f64,
    timestamp: u64,
}

// Implementing the Storable trait for the structs
impl Storable for ParkingSpot {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for ParkingSpot {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for User {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for User {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for Reservation {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Reservation {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for Payment {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Payment {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for Transaction {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Transaction {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

// Implementing the Storable trait for the enums
thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    static ID_COUNTER: RefCell<IdCell> = RefCell::new(
        IdCell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))), 0)
            .expect("Cannot create a counter")
    );

    static PARKING_SPOT_STORAGE: RefCell<StableBTreeMap<u64, ParkingSpot, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))
    ));

    static USER_STORAGE: RefCell<StableBTreeMap<u64, User, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))
    ));

    static RESERVATION_STORAGE: RefCell<StableBTreeMap<u64, Reservation, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3)))
    ));

    static PAYMENT_STORAGE: RefCell<StableBTreeMap<u64, Payment, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(4)))
    ));

    static TRANSACTION_LOG: RefCell<StableBTreeMap<u64, Transaction, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(5)))
    ));
}

//ParkingSpotPayload struct
#[derive(candid::CandidType, Deserialize, Serialize)]
struct ParkingSpotPayload {
    admin_id: u64,
    number_of_spots: u64,
    location: String,
    price_per_hour: f64,
}

// UserPayload struct
#[derive(candid::CandidType, Deserialize, Serialize)]
struct UserPayload {
    username: String,
    password: String,
    email: String,
    phone_number: String,
    first_name: String,
    last_name: String,
}

// ReservationPayload struct
#[derive(candid::CandidType, Deserialize, Serialize)]
struct ReservationPayload {
    user_id: u64,
    spot_id: u64,
    duration_hours: u64,
}

// PaymentPayload struct
#[derive(candid::CandidType, Deserialize, Serialize)]
struct PaymentPayload {
    reservation_id: u64,
    amount: f64,
}

// WithdrawalPayload struct
#[derive(candid::CandidType, Deserialize, Serialize)]
struct WithdrawalPayload {
    user_id: u64,
    amount: f64,
}

// ChangeUserRolePayload struct
#[derive(candid::CandidType, Deserialize, Serialize)]
struct ChangeUserRolePayload {
    user_id: u64,
    role: UserRole,
}

// IsAuthenticatedPayload struct
#[derive(candid::CandidType, Deserialize, Serialize)]
struct IsAuthenticatedPayload {
    user_id: u64,
    password: String,
}

// Message enum
#[derive(candid::CandidType, Deserialize, Serialize, Debug)]
enum Message {
    Success(String),
    Error(String),
    NotFound(String),
    InvalidPayload(String),
}

// Implementing std::fmt::Display for Message
impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::Success(msg) => write!(f, "Success: {}", msg),
            Message::Error(msg) => write!(f, "Error: {}", msg),
            Message::NotFound(msg) => write!(f, "NotFound: {}", msg),
            Message::InvalidPayload(msg) => write!(f, "InvalidPayload: {}", msg),
        }
    }
}

#[ic_cdk::query]
fn get_reservation_by_id(id: u64) -> Result<Reservation, Message> {
    RESERVATION_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, reservation)| reservation.id == id)
            .map(|(_, reservation)| reservation.clone())
            .ok_or(Message::NotFound("Reservation not found".to_string()))
    })
}

// Function to create an admin user
#[ic_cdk::update]
fn create_admin(payload: UserPayload) -> Result<User, Message> {
    if let Err(err) = validate_user_payload(&payload) {
        return Err(Message::InvalidPayload(err));
    }

    if let Err(err) = validate_email(&payload.email) {
        return Err(Message::InvalidPayload(err));
    }

    if !is_email_unique(&payload.email) {
        return Err(Message::InvalidPayload("Email address already exists.".to_string()));
    }

    if let Err(err) = validate_password(&payload.password) {
        return Err(Message::InvalidPayload(err));
    }

    if let Err(err) = validate_phone_number(&payload.phone_number) {
        return Err(Message::InvalidPayload(err));
    }

    let id = increment_id_counter()?;

    let user = User {
        id,
        username: payload.username,
        password: payload.password,
        email: payload.email,
        phone_number: payload.phone_number,
        first_name: payload.first_name,
        last_name: payload.last_name,
        balance: 0.0,
        created_at: current_time(),
        role: UserRole::Admin,
    };

    USER_STORAGE.with(|storage| storage.borrow_mut().insert(id, user.clone()));

    log_transaction(user.id, 0.0, 0.0);

    Ok(user)
}

// Function to create a new user
#[ic_cdk::update]
fn create_user(payload: UserPayload) -> Result<User, Message> {
    if let Err(err) = validate_user_payload(&payload) {
        return Err(Message::InvalidPayload(err));
    }

    if let Err(err) = validate_email(&payload.email) {
        return Err(Message::InvalidPayload(err));
    }

    if !is_email_unique(&payload.email) {
        return Err(Message::InvalidPayload("Email address already exists.".to_string()));
    }

    if let Err(err) = validate_password(&payload.password) {
        return Err(Message::InvalidPayload(err));
    }

    if let Err(err) = validate_phone_number(&payload.phone_number) {
        return Err(Message::InvalidPayload(err));
    }

    let id = increment_id_counter()?;

    let user = User {
        id,
        username: payload.username,
        password: payload.password,
        email: payload.email,
        phone_number: payload.phone_number,
        first_name: payload.first_name,
        last_name: payload.last_name,
        balance: 0.0,
        created_at: current_time(),
        role: UserRole::User,
    };

    USER_STORAGE.with(|storage| storage.borrow_mut().insert(id, user.clone()));

    log_transaction(user.id, 0.0, 0.0);

    Ok(user)
}

// Function to update user information
#[ic_cdk::update]
fn update_user(id: u64, payload: UserPayload) -> Result<User, Message> {
    let mut user = get_user_by_id(id)?.clone();

    if !payload.email.is_empty() && payload.email != user.email {
        if let Err(err) = validate_email(&payload.email) {
            return Err(Message::InvalidPayload(err));
        }

        if !is_email_unique(&payload.email) {
            return Err(Message::InvalidPayload("Email address already exists.".to_string()));
        }
    }

    if !payload.password.is_empty() {
        if let Err(err) = validate_password(&payload.password) {
            return Err(Message::InvalidPayload(err));
        }

        user.password = payload.password;
    }

    if let Err(err) = validate_phone_number(&payload.phone_number) {
        return Err(Message::InvalidPayload(err));
    }

    user.username = payload.username;
    user.email = payload.email;
    user.phone_number = payload.phone_number;
    user.first_name = payload.first_name;
    user.last_name = payload.last_name;

    USER_STORAGE.with(|storage| storage.borrow_mut().insert(user.id, user.clone()));

    Ok(user)
}

// Function to get a user by ID
#[ic_cdk::query]
fn get_user_by_id(id: u64) -> Result<User, Message> {
    USER_STORAGE.with(|storage| {
        storage
            .borrow()
            .get(&id)
            .map(|user| user.clone())
            .ok_or(Message::NotFound("User not found".to_string()))
    })
}

// Function to change user roles
#[ic_cdk::update]
fn change_user_role(payload: ChangeUserRolePayload) -> Result<User, Message> {
    let mut user = get_user_by_id(payload.user_id)?;

    user.role = payload.role;

    USER_STORAGE.with(|storage| storage.borrow_mut().insert(user.id, user.clone()));

    Ok(user)
}

// Function to create a parking spot
#[ic_cdk::update]
fn create_parking_spot(payload: ParkingSpotPayload) -> Result<ParkingSpot, Message> {
    if payload.location.is_empty() || payload.price_per_hour <= 0.0 || payload.number_of_spots == 0 {
        return Err(Message::InvalidPayload(
            "Ensure 'location', 'price_per_hour', and 'number_of_spots' are provided.".to_string(),
        ));
    }

    if let Err(err) = is_admin(payload.admin_id) {
        return Err(Message::Error(err.to_string()));
    }

    let id = increment_id_counter()?;

    let parking_spot = ParkingSpot {
        id,
        admin_id: payload.admin_id,
        number_of_spots: payload.number_of_spots,
        location: payload.location,
        status: ParkingSlotStatus::Available,
        price_per_hour: payload.price_per_hour,
        created_at: current_time(),
    };

    PARKING_SPOT_STORAGE.with(|storage| storage.borrow_mut().insert(id, parking_spot.clone()));

    Ok(parking_spot)
}

// Function to update parking spot status
#[ic_cdk::update]
fn update_parking_spot_status(id: u64, status: ParkingSlotStatus) -> Result<ParkingSpot, Message> {
    let mut spot = get_parking_spot_by_id(id)?;

    spot.status = status;

    PARKING_SPOT_STORAGE.with(|storage| storage.borrow_mut().insert(spot.id, spot.clone()));

    Ok(spot)
}

// Function to get a parking spot by ID
#[ic_cdk::query]
fn get_parking_spot_by_id(id: u64) -> Result<ParkingSpot, Message> {
    PARKING_SPOT_STORAGE.with(|storage| {
        storage
            .borrow()
            .get(&id)
            .map(|spot| spot.clone())
            .ok_or(Message::NotFound("Parking spot not found".to_string()))
    })
}

// Function to create a reservation
#[ic_cdk::update]
fn create_reservation(payload: ReservationPayload) -> Result<Reservation, Message> {
    if payload.duration_hours == 0 {
        return Err(Message::InvalidPayload("Ensure 'duration_hours' is greater than zero.".to_string()));
    }

    let user = get_user_by_id(payload.user_id)?;
    let mut spot = get_parking_spot_by_id(payload.spot_id)?;

    if spot.number_of_spots == 0 {
        return Err(Message::InvalidPayload("No available parking spots.".to_string()));
    }

    let amount_payable = spot.price_per_hour * payload.duration_hours as f64;

    spot.number_of_spots -= 1;
    PARKING_SPOT_STORAGE.with(|storage| storage.borrow_mut().insert(spot.id, spot.clone()));

    let id = increment_id_counter()?;

    let reservation = Reservation {
        id,
        user_id: payload.user_id,
        spot_id: payload.spot_id,
        reserved_at: current_time(),
        duration_hours: payload.duration_hours,
        status: "reserved".to_string(),
        amount_payable,
        created_at: current_time(),
    };

    RESERVATION_STORAGE.with(|storage| storage.borrow_mut().insert(id, reservation.clone()));

    Ok(reservation)
}

// Function to create a payment
#[ic_cdk::update]
fn create_payment(payload: PaymentPayload) -> Result<Payment, Message> {
    if payload.amount <= 0.0 {
        return Err(Message::InvalidPayload("Ensure 'amount' is greater than zero.".to_string()));
    }

    let reservation = get_reservation_by_id(payload.reservation_id)?;

    let spot = get_parking_spot_by_id(reservation.spot_id)?;

    let expected_amount = spot.price_per_hour * reservation.duration_hours as f64;

    if (payload.amount - expected_amount).abs() > f64::EPSILON {
        return Err(Message::InvalidPayload("Payment amount does not match the expected amount.".to_string()));
    }

    let user = get_user_by_id(reservation.user_id)?;

    if user.balance < expected_amount {
        return Err(Message::InvalidPayload("Insufficient balance.".to_string()));
    }

    let updated_user = User {
        balance: user.balance - expected_amount,
        ..user
    };

    USER_STORAGE.with(|storage| storage.borrow_mut().insert(user.id, updated_user.clone()));

    let admin = get_user_by_id(spot.admin_id)?;

    let updated_admin = User {
        balance: admin.balance + expected_amount,
        ..admin
    };

    USER_STORAGE.with(|storage| storage.borrow_mut().insert(admin.id, updated_admin.clone()));

    let id = increment_id_counter()?;

    let payment = Payment {
        id,
        reservation_id: payload.reservation_id,
        amount: payload.amount,
        status: "completed".to_string(),
        created_at: current_time(),
    };

    PAYMENT_STORAGE.with(|storage| storage.borrow_mut().insert(id, payment.clone()));

    Ok(payment)
}

// Function to deposit funds
#[ic_cdk::update]
fn deposit_funds(
    payload: WithdrawalPayload,
    payload1: IsAuthenticatedPayload,
) -> Result<Message, Message> {
    if payload.amount <= 0.0 {
        return Err(Message::InvalidPayload("Ensure 'amount' is greater than zero.".to_string()));
    }

    is_authenticated(payload1)?;

    let mut user = get_user_by_id(payload.user_id)?;

    user.balance += payload.amount;

    USER_STORAGE.with(|storage| storage.borrow_mut().insert(user.id, user.clone()));

    log_transaction(user.id, payload.amount, 0.0);

    Ok(Message::Success(format!("Deposit of {} successful.", payload.amount)))
}

// Function to withdraw funds
#[ic_cdk::update]
fn withdraw_funds(
    payload: WithdrawalPayload,
    payload1: IsAuthenticatedPayload,
) -> Result<Message, Message> {
    if payload.amount <= 0.0 {
        return Err(Message::InvalidPayload("Ensure 'amount' is greater than zero.".to_string()));
    }

    is_authenticated(payload1)?;

    is_admin(payload.user_id)?;

    let fee = payload.amount * 0.01;
    let amount_after_fee = payload.amount - fee;

    let mut user = get_user_by_id(payload.user_id)?;

    if user.balance < amount_after_fee {
        return Err(Message::InvalidPayload("Insufficient balance.".to_string()));
    }

    user.balance -= amount_after_fee;

    USER_STORAGE.with(|storage| storage.borrow_mut().insert(user.id, user.clone()));

    log_transaction(user.id, amount_after_fee, fee);

    Ok(Message::Success(format!(
        "Withdrawal of {} successful. Fee applied: {}.",
        amount_after_fee, fee
    )))
}

// Function to log transactions
fn log_transaction(user_id: u64, amount: f64, fee: f64) {
    let timestamp = current_time();

    let transaction = Transaction {
        user_id,
        amount,
        fee,
        timestamp,
    };

    TRANSACTION_LOG.with(|log| log.borrow_mut().insert(timestamp, transaction));
}

// Helper Functions
fn increment_id_counter() -> Result<u64, Message> {
    ID_COUNTER.with(|counter: &RefCell<IdCell>| {
        let current_value = *counter.borrow().get();
        counter.borrow_mut().set(current_value + 1).map_err(|_| Message::Error("Cannot increment ID counter".to_string()))?;
        Ok(current_value + 1)
    })
}

fn is_admin(user_id: u64) -> Result<(), Message> {
    USER_STORAGE.with(|storage| {
        storage.borrow().get(&user_id).and_then(|user| {
            if user.role == UserRole::Admin {
                Some(())
            } else {
                None
            }
        }).ok_or(Message::Error("User is not an admin".to_string()))
    })
}

fn is_authenticated(payload: IsAuthenticatedPayload) -> Result<(), Message> {
    USER_STORAGE.with(|storage| {
        storage.borrow().get(&payload.user_id).and_then(|user| {
            if user.password == payload.password {
                Some(())
            } else {
                None
            }
        }).ok_or(Message::Error("Invalid credentials".to_string()))
    })
}

fn validate_user_payload(payload: &UserPayload) -> Result<(), String> {
    if payload.username.is_empty()
        || payload.password.is_empty()
        || payload.email.is_empty()
        || payload.phone_number.is_empty()
        || payload.first_name.is_empty()
        || payload.last_name.is_empty()
    {
        return Err("Ensure 'username', 'password', 'email', 'phone_number', 'first_name', and 'last_name' are provided.".to_string());
    }

    Ok(())
}

fn validate_password(password: &str) -> Result<(), String> {
    let min_length = 8;
    let has_uppercase = Regex::new(r"[A-Z]").unwrap();
    let has_lowercase = Regex::new(r"[a-z]").unwrap();
    let has_digit = Regex::new(r"\d").unwrap();
    let has_special_char = Regex::new(r"[^A-Za-z0-9]").unwrap();
    let has_whitespace = Regex::new(r"\s").unwrap();

    if password.len() < min_length {
        return Err("Password must be at least 8 characters long.".to_string());
    }

    if has_whitespace.is_match(password) {
        return Err("Password must not contain whitespace characters.".to_string());
    }

    if !has_uppercase.is_match(password) {
        return Err("Password must contain at least one uppercase letter.".to_string());
    }

    if !has_lowercase.is_match(password) {
        return Err("Password must contain at least one lowercase letter.".to_string());
    }

    if !has_digit.is_match(password) {
        return Err("Password must contain at least one digit.".to_string());
    }

    if !has_special_char.is_match(password) {
        return Err("Password must contain at least one special character.".to_string());
    }

    Ok(())
}

fn validate_email(email: &str) -> Result<(), String> {
    let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    if !email_regex.is_match(email) {
        return Err("Invalid email address.".to_string());
    }

    Ok(())
}

fn validate_phone_number(phone_number: &str) -> Result<(), String> {
    let phone_number_regex = Regex::new(r"^\+?1?\d{9,15}$").unwrap();
    if !phone_number_regex.is_match(phone_number) {
        return Err("Invalid phone number.".to_string());
    }

    Ok(())
}

fn is_email_unique(email: &str) -> bool {
    USER_STORAGE.with(|storage| storage.borrow().iter().all(|(_, user)| user.email != email))
}

fn current_time() -> u64 {
    time()
}

// Error type for the application
#[derive(candid::CandidType, Deserialize, Serialize, Debug)]
enum Error {
    NotFound { msg: String },
    UnAuthorized { msg: String },
}

// Implement the std::fmt::Display trait for the Error enum
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::NotFound { ref msg } => write!(f, "NotFound: {}", msg),
            Error::UnAuthorized { ref msg } => write!(f, "UnAuthorized: {}", msg),
        }
    }
}

// Implement the std::error::Error trait for the Error enum
impl std::error::Error for Error {}

ic_cdk::export_candid!();
