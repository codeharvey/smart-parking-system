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
#[derive(candid::CandidType, Deserialize, Serialize)]
enum Message {
    Success(String),
    Error(String),
    NotFound(String),
    InvalidPayload(String),
}

// Function to create an admin user
#[ic_cdk::update]
fn create_admin(payload: UserPayload) -> Result<User, Message> {
    // Validate the payload to ensure all required fields are provided
    if payload.username.is_empty()
        || payload.password.is_empty()
        || payload.email.is_empty()
        || payload.phone_number.is_empty()
        || payload.first_name.is_empty()
        || payload.last_name.is_empty()
    {
        return Err(Message::InvalidPayload(
            "Ensure 'username', 'password', 'email', 'phone_number', 'first_name', and 'last_name' are provided.".to_string(),
        ));
    }

    // Validate the email address
    if let Err(err) = validate_email(&payload.email) {
        return Err(Message::InvalidPayload(err));
    }

    // Ensure email uniqueness
    if !is_email_unique(&payload.email) {
        return Err(Message::InvalidPayload(
            "Email address already exists.".to_string(),
        ));
    }

    // Validate the password strength
    if let Err(err) = validate_password(&payload.password) {
        return Err(Message::InvalidPayload(err));
    }

    // Validate the phone number
    if let Err(err) = validate_phone_number(&payload.phone_number) {
        return Err(Message::InvalidPayload(err));
    }

    // Increment the ID counter to generate a new ID for the user
    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let user = User {
        id,
        username: payload.username,
        password: payload.password,
        email: payload.email,
        phone_number: payload.phone_number,
        first_name: payload.first_name,
        last_name: payload.last_name,
        balance: 0.0, // Initialize balance to zero
        created_at: current_time(),
        role: UserRole::Admin,
    };

    // Store the user in the memory
    USER_STORAGE.with(|storage| storage.borrow_mut().insert(id, user.clone()));
    Ok(user)
}

// Function to get all admin users
#[ic_cdk::query]
fn get_admins() -> Result<Vec<User>, Message> {
    // Retrieve all admin users from the memory
    USER_STORAGE.with(|storage| {
        let admins: Vec<User> = storage
            .borrow()
            .iter()
            .filter(|(_, user)| user.role == UserRole::Admin)
            .map(|(_, user)| user.clone())
            .collect();

        if admins.is_empty() {
            Err(Message::NotFound("No admins found".to_string()))
        } else {
            Ok(admins)
        }
    })
}

// Function for admin to change user roles
#[ic_cdk::update]
fn change_user_role(payload: ChangeUserRolePayload) -> Result<User, Message> {
    // Validate the user id to ensure it exists
    let user = USER_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, user)| user.id == payload.user_id)
            .map(|(_, user)| user.clone())
    });
    if user.is_none() {
        return Err(Message::NotFound("User not found".to_string()));
    }

    // Update the user role
    let user = user.unwrap();
    let updated_user = User {
        role: payload.role,
        ..user
    };

    // Store the updated user in the memory
    USER_STORAGE.with(|storage| storage.borrow_mut().insert(user.id, updated_user.clone()));
    Ok(updated_user)
}

// Function to create a new user
#[ic_cdk::update]
fn create_user(payload: UserPayload) -> Result<User, Message> {
    // Validate the payload to ensure all required fields are provided
    if payload.username.is_empty()
        || payload.password.is_empty()
        || payload.email.is_empty()
        || payload.phone_number.is_empty()
        || payload.first_name.is_empty()
        || payload.last_name.is_empty()
    {
        return Err(Message::InvalidPayload(
            "Ensure 'username', 'password', 'email', 'phone_number', 'first_name', and 'last_name' are provided.".to_string(),
        ));
    }

    // Validate the email address
    if let Err(err) = validate_email(&payload.email) {
        return Err(Message::InvalidPayload(err));
    }

    // Ensure email uniqueness
    if !is_email_unique(&payload.email) {
        return Err(Message::InvalidPayload(
            "Email address already exists.".to_string(),
        ));
    }

    // Validate the password strength
    if let Err(err) = validate_password(&payload.password) {
        return Err(Message::InvalidPayload(err));
    }

    // Validate the phone number
    if let Err(err) = validate_phone_number(&payload.phone_number) {
        return Err(Message::InvalidPayload(err));
    }

    // Increment the ID counter to generate a new ID for the user
    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let user = User {
        id,
        username: payload.username,
        password: payload.password,
        email: payload.email,
        phone_number: payload.phone_number,
        first_name: payload.first_name,
        last_name: payload.last_name,
        balance: 0.0, // Initialize balance to zero
        created_at: current_time(),
        role: UserRole::User, // Default role is User
    };

    // Store the user in the memory
    USER_STORAGE.with(|storage| storage.borrow_mut().insert(id, user.clone()));
    Ok(user)
}

// Function to get all users
#[ic_cdk::query]
fn get_users() -> Result<Vec<User>, Message> {
    // Retrieve all users from the memory
    USER_STORAGE.with(|storage| {
        let users: Vec<User> = storage
            .borrow()
            .iter()
            .map(|(_, user)| user.clone())
            .collect();

        if users.is_empty() {
            Err(Message::NotFound("No users found".to_string()))
        } else {
            Ok(users)
        }
    })
}

// Function to get a user by ID
#[ic_cdk::query]
fn get_user_by_id(id: u64) -> Result<User, Message> {
    USER_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, user)| user.id == id)
            .map(|(_, user)| user.clone())
            .ok_or(Message::NotFound("User not found".to_string()))
    })
}

// Function to create a parking spot
#[ic_cdk::update]
fn create_parking_spot(payload: ParkingSpotPayload) -> Result<ParkingSpot, Message> {
    // Validate the payload to ensure all required fields are provided
    if payload.location.is_empty() || payload.price_per_hour <= 0.0 || payload.number_of_spots == 0
    {
        return Err(Message::InvalidPayload(
            "Ensure 'location', 'price_per_hour', and 'number_of_spots' are provided.".to_string(),
        ));
    }

    // Ensure the admin is the one creating the parking spot
    if let Err(err) = is_admin(payload.admin_id) {
        return Err(Message::Error(err.to_string()));
    }

    // Increment the ID counter to generate a new ID for the parking spot
    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let parking_spot = ParkingSpot {
        id,
        admin_id: payload.admin_id,
        number_of_spots: payload.number_of_spots,
        location: payload.location,
        status: ParkingSlotStatus::Available,
        price_per_hour: payload.price_per_hour,
        created_at: current_time(),
    };

    // Store the parking spot in the memory
    PARKING_SPOT_STORAGE.with(|storage| storage.borrow_mut().insert(id, parking_spot.clone()));
    Ok(parking_spot)
}

// Function to get all parking spots
#[ic_cdk::query]
fn get_parking_spots() -> Result<Vec<ParkingSpot>, Message> {
    // Retrieve all parking spots from the memory
    PARKING_SPOT_STORAGE.with(|storage| {
        let spots: Vec<ParkingSpot> = storage
            .borrow()
            .iter()
            .map(|(_, spot)| spot.clone())
            .collect();

        if spots.is_empty() {
            Err(Message::NotFound("No parking spots found".to_string()))
        } else {
            Ok(spots)
        }
    })
}

// Function to get a parking spot by ID
#[ic_cdk::query]
fn get_parking_spot_by_id(id: u64) -> Result<ParkingSpot, Message> {
    PARKING_SPOT_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, spot)| spot.id == id)
            .map(|(_, spot)| spot.clone())
            .ok_or(Message::NotFound("Parking spot not found".to_string()))
    })
}

// Function to create a reservation
#[ic_cdk::update]
fn create_reservation(payload: ReservationPayload) -> Result<Reservation, Message> {
    // Validate the payload to ensure all required fields are provided
    if payload.duration_hours == 0 {
        return Err(Message::InvalidPayload(
            "Ensure 'duration_hours' is greater than zero.".to_string(),
        ));
    }

    // Validate the user id to ensure it exists
    let user = USER_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, user)| user.id == payload.user_id)
            .map(|(_, user)| user.clone())
    });
    if user.is_none() {
        return Err(Message::NotFound("User not found".to_string()));
    }

    // Validate the parking spot id to ensure it exists
    let spot = PARKING_SPOT_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, spot)| spot.id == payload.spot_id)
            .map(|(_, spot)| spot.clone())
    });
    if spot.is_none() {
        return Err(Message::NotFound("Parking spot not found".to_string()));
    }

    // Ensure there are available parking spots
    let spot = spot.unwrap();
    if spot.number_of_spots == 0 {
        return Err(Message::InvalidPayload(
            "No available parking spots.".to_string(),
        ));
    }

    // Calculate amount payable based on the reservation duration and parking spot price
    let amount_payable = spot.price_per_hour * payload.duration_hours as f64;

    // Reduce the number of available parking spots
    let updated_spot = ParkingSpot {
        number_of_spots: spot.number_of_spots - 1,
        ..spot
    };

    PARKING_SPOT_STORAGE.with(|storage| storage.borrow_mut().insert(spot.id, updated_spot.clone()));

    // Increment the ID counter to generate a new ID for the reservation
    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

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

    // Store the reservation in the memory
    RESERVATION_STORAGE.with(|storage| storage.borrow_mut().insert(id, reservation.clone()));
    Ok(reservation)
}

// Function to get all reservations
#[ic_cdk::query]
fn get_reservations() -> Result<Vec<Reservation>, Message> {
    RESERVATION_STORAGE.with(|storage| {
        let reservations: Vec<Reservation> = storage
            .borrow()
            .iter()
            .map(|(_, reservation)| reservation.clone())
            .collect();

        if reservations.is_empty() {
            Err(Message::NotFound("No reservations found".to_string()))
        } else {
            Ok(reservations)
        }
    })
}

// Function to get a reservation by ID
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

// Function to create a payment
#[ic_cdk::update]
fn create_payment(payload: PaymentPayload) -> Result<Payment, Message> {
    // Validate the user payload to ensure all required fields are provided
    if payload.amount <= 0.0 {
        return Err(Message::InvalidPayload(
            "Ensure 'amount' is greater than zero.".to_string(),
        ));
    }

    // Validate the reservation id to ensure it exists
    let reservation = RESERVATION_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, reservation)| reservation.id == payload.reservation_id)
            .map(|(_, reservation)| reservation.clone())
    });
    if reservation.is_none() {
        return Err(Message::NotFound("Reservation not found".to_string()));
    }

    // Validate the payment amount to ensure it matches the expected amount
    let reservation = reservation.unwrap();

    // Calculate the expected payment amount based on the reservation duration and parking spot price
    let spot = PARKING_SPOT_STORAGE
        .with(|storage| {
            storage
                .borrow()
                .iter()
                .find(|(_, spot)| spot.id == reservation.spot_id)
                .map(|(_, spot)| spot.clone())
        })
        .unwrap();

    let expected_amount = spot.price_per_hour * reservation.duration_hours as f64;

    if (payload.amount - expected_amount).abs() > f64::EPSILON {
        return Err(Message::InvalidPayload(
            "Payment amount does not match the expected amount.".to_string(),
        ));
    }
    // If the amount paid by the user is greater than the amount payable
    // refund the excess amount to the user
    if payload.amount > expected_amount {
        let excess_amount = payload.amount - expected_amount;
        let user = USER_STORAGE.with(|storage| {
            storage
                .borrow()
                .iter()
                .find(|(_, user)| user.id == reservation.user_id)
                .map(|(_, user)| user.clone())
        });

        if user.is_none() {
            return Err(Message::NotFound("User not found".to_string()));
        }

        let user = user.unwrap();
        let updated_user = User {
            balance: user.balance + excess_amount,
            ..user
        };

        USER_STORAGE.with(|storage| storage.borrow_mut().insert(user.id, updated_user.clone()));
    }

    // Deduct the amount from the user's balance
    let user_updated = USER_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        if let Some(mut user) = storage.remove(&reservation.user_id) {
            if user.balance >= expected_amount {
                user.balance -= expected_amount;
                storage.insert(reservation.user_id, user);
                Ok(())
            } else {
                Err(Message::InvalidPayload("Insufficient balance.".to_string()))
            }
        } else {
            Err(Message::NotFound("User not found".to_string()))
        }
    });

    if user_updated.is_err() {
        return user_updated.map(|_| Payment {
            id: 0,
            reservation_id: 0,
            amount: 0.0,
            status: "".to_string(),
            created_at: 0,
        });
    }

    // Update the admin's balance using the admin_id field in the ParkingSpot
    let admin_id = spot.admin_id;

    let admin_updated = USER_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        if let Some(mut admin) = storage.remove(&admin_id) {
            admin.balance += expected_amount;
            storage.insert(admin_id, admin);
            Ok(())
        } else {
            Err(Message::NotFound("Admin not found".to_string()))
        }
    });

    if admin_updated.is_err() {
        return admin_updated.map(|_| Payment {
            id: 0,
            reservation_id: 0,
            amount: 0.0,
            status: "".to_string(),
            created_at: 0,
        });
    }

    // Increment the ID counter to generate a new ID for the payment
    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

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

// Function for a user to deposit funds
#[ic_cdk::update]
fn deposit_funds(
    payload: WithdrawalPayload,
    payload1: IsAuthenticatedPayload,
) -> Result<Message, Message> {
    // Validate the payload to ensure all required fields are provided
    if payload.amount <= 0.0 {
        return Err(Message::InvalidPayload(
            "Ensure 'amount' is greater than zero.".to_string(),
        ));
    }

    // Ensure the user is authenticated
    if let Err(err) = is_authenticated(payload1) {
        return Err(Message::Error(err.to_string()));
    }

    // Validate the user id to ensure it exists
    let user = USER_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, user)| user.id == payload.user_id)
            .map(|(_, user)| user.clone())
    });

    if user.is_none() {
        return Err(Message::NotFound("User not found".to_string()));
    }

    let user = user.unwrap();
    let updated_user = User {
        balance: user.balance + payload.amount,
        ..user
    };

    USER_STORAGE.with(|storage| storage.borrow_mut().insert(user.id, updated_user.clone()));

    // Log the transaction
    TRANSACTION_LOG.with(|log| {
        log.borrow_mut().insert(
            current_time(),
            Transaction {
                user_id: payload.user_id,
                amount: payload.amount,
                fee: 0.0,
                timestamp: current_time(),
            },
        )
    });

    // Return a success message
    Ok(Message::Success(format!(
        "Deposit of {} successful.",
        payload.amount
    )))
}

// Function to withdraw funds from a user's balance
#[ic_cdk::update]
fn withdraw_funds(
    payload: WithdrawalPayload,
    payload1: IsAuthenticatedPayload,
) -> Result<Message, Message> {
    if payload.amount <= 0.0 {
        return Err(Message::InvalidPayload(
            "Ensure 'amount' is greater than zero.".to_string(),
        ));
    }

    // Ensure the user is authenticated
    if let Err(err) = is_authenticated(payload1) {
        return Err(Message::Error(err.to_string()));
    }

    // Ensure the admin is the one withdrawing the funds
    if let Err(err) = is_admin(payload.user_id) {
        return Err(Message::Error(err.to_string()));
    }

    // Apply transaction fee (e.g., 1%)
    let fee = payload.amount * 0.01;
    let amount_after_fee = payload.amount - fee;

    // Ensure the user has sufficient balance
    let user = USER_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, user)| amount_after_fee <= user.balance)
            .map(|(_, user)| user.clone())
    });

    if user.is_none() {
        return Err(Message::InvalidPayload("Insufficient balance.".to_string()));
    }

    // Deduct the amount from the user's balance
    let user = user.unwrap();
    let updated_user = User {
        balance: user.balance - amount_after_fee,
        ..user
    };

    USER_STORAGE.with(|storage| storage.borrow_mut().insert(user.id, updated_user.clone()));

    // Log the transaction
    TRANSACTION_LOG.with(|log| {
        log.borrow_mut().insert(
            current_time(),
            Transaction {
                user_id: payload.user_id,
                amount: payload.amount,
                fee,
                timestamp: current_time(),
            },
        )
    });

    // Return a success message
    Ok(Message::Success(format!(
        "Withdrawal of {} successful. Fee applied: {}.",
        amount_after_fee, fee
    )))
}

// Function to get all payments
#[ic_cdk::query]
fn get_payments() -> Result<Vec<Payment>, Message> {
    PAYMENT_STORAGE.with(|storage| {
        let payments: Vec<Payment> = storage
            .borrow()
            .iter()
            .map(|(_, payment)| payment.clone())
            .collect();

        if payments.is_empty() {
            Err(Message::NotFound("No payments found".to_string()))
        } else {
            Ok(payments)
        }
    })
}

// Function to get a payment by ID
#[ic_cdk::query]
fn get_payment_by_id(id: u64) -> Result<Payment, Message> {
    PAYMENT_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, payment)| payment.id == id)
            .map(|(_, payment)| payment.clone())
            .ok_or(Message::NotFound("Payment not found".to_string()))
    })
}

// Function to get all transactions
#[ic_cdk::query]
fn get_transactions() -> Result<Vec<Transaction>, Message> {
    TRANSACTION_LOG.with(|log| {
        let transactions: Vec<Transaction> = log
            .borrow()
            .iter()
            .map(|(_, transaction)| transaction.clone())
            .collect();

        if transactions.is_empty() {
            Err(Message::NotFound("No transactions found".to_string()))
        } else {
            Ok(transactions)
        }
    })
}

// Function to get a transaction by timestamp
#[ic_cdk::query]
fn get_transaction_by_timestamp(timestamp: u64) -> Result<Transaction, Message> {
    TRANSACTION_LOG.with(|log| {
        log.borrow()
            .iter()
            .find(|(_, transaction)| transaction.timestamp == timestamp)
            .map(|(_, transaction)| transaction.clone())
            .ok_or(Message::NotFound("Transaction not found".to_string()))
    })
}

// Function to get all transactions for a user
#[ic_cdk::query]
fn get_user_transactions(user_id: u64) -> Result<Vec<Transaction>, Message> {
    TRANSACTION_LOG.with(|log| {
        let transactions: Vec<Transaction> = log
            .borrow()
            .iter()
            .filter(|(_, transaction)| transaction.user_id == user_id)
            .map(|(_, transaction)| transaction.clone())
            .collect();

        if transactions.is_empty() {
            Err(Message::NotFound("No transactions found".to_string()))
        } else {
            Ok(transactions)
        }
    })
}

// Helper Functions

// Permissions based on the user roles
fn is_admin(user_id: u64) -> Result<(), Error> {
    USER_STORAGE.with(|storage| {
        if let Some(user) = storage.borrow().get(&user_id) {
            if user.role == UserRole::Admin {
                Ok(())
            } else {
                Err(Error::UnAuthorized {
                    msg: "User is not an admin".to_string(),
                })
            }
        } else {
            Err(Error::NotFound {
                msg: "User not found".to_string(),
            })
        }
    })
}

fn is_user(user_id: u64) -> Result<(), Error> {
    USER_STORAGE.with(|storage| {
        if let Some(user) = storage.borrow().get(&user_id) {
            if user.role == UserRole::User {
                Ok(())
            } else {
                Err(Error::UnAuthorized {
                    msg: "User does not have the required role".to_string(),
                })
            }
        } else {
            Err(Error::NotFound {
                msg: "User not found".to_string(),
            })
        }
    })
}

// Function to check user authentication
fn is_authenticated(payload: IsAuthenticatedPayload) -> Result<(), Error> {
    USER_STORAGE.with(|storage| {
        if let Some(user) = storage.borrow().get(&payload.user_id) {
            if user.password == payload.password {
                Ok(())
            } else {
                Err(Error::UnAuthorized {
                    msg: "Invalid password".to_string(),
                })
            }
        } else {
            Err(Error::NotFound {
                msg: "User not found".to_string(),
            })
        }
    })
}

// Helper function to get the current time
fn current_time() -> u64 {
    time()
}

// Helper function to validate the password strength
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

// Helper function to validate the user email address
fn validate_email(email: &str) -> Result<(), String> {
    let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    if !email_regex.is_match(email) {
        return Err("Invalid email address.".to_string());
    }

    Ok(())
}

// Helper function to validate the user phone number
fn validate_phone_number(phone_number: &str) -> Result<(), String> {
    let phone_number_regex = Regex::new(r"^\+?1?\d{9,15}$").unwrap();
    if !phone_number_regex.is_match(phone_number) {
        return Err("Invalid phone number.".to_string());
    }

    Ok(())
}

// Helper to make sure the user email address is unique
fn is_email_unique(email: &str) -> bool {
    USER_STORAGE.with(|storage| storage.borrow().iter().all(|(_, user)| user.email != email))
}

// Helper Function to check withdrawal limits
fn check_withdrawal_limits(user_id: u64, amount: f64) -> Result<(), Error> {
    let user = USER_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, user)| user.id == user_id)
            .map(|(_, user)| user.clone())
    });

    if user.is_none() {
        return Err(Error::NotFound {
            msg: "User not found".to_string(),
        });
    }

    let user = user.unwrap();
    if user.balance < amount {
        return Err(Error::UnAuthorized {
            msg: "Insufficient balance".to_string(),
        });
    }

    Ok(())
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
