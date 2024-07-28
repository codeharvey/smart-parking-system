# Smart Parking System

This project is a smart parking system implemented on the Internet Computer using Rust and the Candid interface. It allows for the creation, management, and utilization of parking spots, user accounts, reservations, payments, and transactions.

## Features

- **User Roles**: Users can be assigned roles such as `User` or `Admin`.
- **Parking Spots**: Admins can create parking spots with a specified location, price per hour, and the number of spots available.
- **Reservations**: Users can reserve parking spots for a specified duration.
- **Payments**: Users can make payments for their reservations. The system ensures the payment amount matches the expected amount and handles user balances.
- **Transactions**: Logs all transactions for audit purposes.
- **Authentication**: Ensures users are authenticated before performing certain actions.
- **Deposits and Withdrawals**: Users can deposit and withdraw funds, with admin oversight.

## Data Structures

### Enums

- **UserRole**: Defines user roles (`User`, `Admin`).
- **ParkingSlotStatus**: Defines the status of a parking slot (`Available`, `Occupied`).
- **Message**: Defines various message types for function results (`Success`, `Error`, `NotFound`, `InvalidPayload`).
- **Error**: Defines error types (`NotFound`, `UnAuthorized`).

### Structs

- **ParkingSpot**: Represents a parking spot with fields for ID, admin ID, location, status, price per hour, number of spots, and creation time.
- **User**: Represents a user with fields for ID, username, password, role, email, phone number, first name, last name, balance, and creation time.
- **Reservation**: Represents a reservation with fields for ID, user ID, spot ID, reservation time, duration in hours, status, amount payable, and creation time.
- **Payment**: Represents a payment with fields for ID, reservation ID, amount, status, and creation time.
- **Transaction**: Represents a transaction with fields for user ID, amount, fee, and timestamp.

### Payload Structs

- **ParkingSpotPayload**: Represents the payload to create a parking spot.
- **UserPayload**: Represents the payload to create a user.
- **ReservationPayload**: Represents the payload to create a reservation.
- **PaymentPayload**: Represents the payload to create a payment.
- **WithdrawalPayload**: Represents the payload to deposit or withdraw funds.
- **ChangeUserRolePayload**: Represents the payload to change a user's role.
- **IsAuthenticatedPayload**: Represents the payload to check if a user is authenticated.

## Functions

### User Functions

- **create_admin**: Creates an admin user.
- **create_user**: Creates a regular user.
- **get_admins**: Retrieves all admin users.
- **get_users**: Retrieves all users.
- **get_user_by_id**: Retrieves a user by ID.
- **change_user_role**: Changes a user's role.

### Parking Spot Functions

- **create_parking_spot**: Creates a new parking spot.
- **get_parking_spots**: Retrieves all parking spots.
- **get_parking_spot_by_id**: Retrieves a parking spot by ID.

### Reservation Functions

- **create_reservation**: Creates a new reservation.
- **get_reservations**: Retrieves all reservations.
- **get_reservation_by_id**: Retrieves a reservation by ID.

### Payment Functions

- **create_payment**: Creates a new payment for a reservation.
- **get_payments**: Retrieves all payments.
- **get_payment_by_id**: Retrieves a payment by ID.

### Transaction Functions

- **get_transactions**: Retrieves all transactions.
- **get_transaction_by_timestamp**: Retrieves a transaction by timestamp.
- **get_user_transactions**: Retrieves all transactions for a user.

### Balance Management Functions

- **deposit_funds**: Deposits funds into a user's balance.
- **withdraw_funds**: Withdraws funds from a user's balance.

## Helper Functions

- **is_admin**: Checks if a user is an admin.
- **is_user**: Checks if a user is a regular user.
- **is_authenticated**: Checks if a user is authenticated.
- **current_time**: Gets the current time.
- **validate_password**: Validates the strength of a password.
- **validate_email**: Validates the format of an email address.
- **validate_phone_number**: Validates the format of a phone number.
- **is_email_unique**: Checks if an email address is unique.
- **check_withdrawal_limits**: Checks if a user has sufficient balance for a withdrawal.

## Error Handling

The system uses the `Error` enum to handle different types of errors, including `NotFound` and `UnAuthorized` errors. Each error type includes a message providing more details about the error.

## Requirements

- rustc 1.64 or higher

```bash
$ curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
$ source "$HOME/.cargo/env"
```

- rust wasm32-unknown-unknown target

```bash
$ rustup target add wasm32-unknown-unknown
```

- candid-extractor

```bash
$ cargo install candid-extractor
```

- install `dfx`

```bash
$ DFX_VERSION=0.15.0 sh -ci "$(curl -fsSL https://sdk.dfinity.org/install.sh)"
$ echo 'export PATH="$PATH:$HOME/bin"' >> "$HOME/.bashrc"
$ source ~/.bashrc
$ dfx start --background
```

If you want to start working on your project right away, you might want to try the following commands:

```bash
$ cd icp_rust_boilerplate/
$ dfx help
$ dfx canister --help
```

## Update dependencies

update the `dependencies` block in `/src/{canister_name}/Cargo.toml`:

```
[dependencies]
candid = "0.9.9"
ic-cdk = "0.11.1"
serde = { version = "1", features = ["derive"] }
serde_json = "1.0"
ic-stable-structures = { git = "https://github.com/lwshang/stable-structures.git", branch = "lwshang/update_cdk"}
```

## did autogenerate

Add this script to the root directory of the project:

```
https://github.com/buildwithjuno/juno/blob/main/scripts/did.sh
```

Update line 16 with the name of your canister:

```
https://github.com/buildwithjuno/juno/blob/main/scripts/did.sh#L16
```

After this run this script to generate Candid.
Important note!

You should run this script each time you modify/add/remove exported functions of the canister.
Otherwise, you'll have to modify the candid file manually.

Also, you can add package json with this content:

```
{
    "scripts": {
        "generate": "./did.sh && dfx generate",
        "gen-deploy": "./did.sh && dfx generate && dfx deploy -y"
      }
}
```

and use commands `npm run generate` to generate candid or `npm run gen-deploy` to generate candid and to deploy a canister.

## Running the project locally

If you want to test your project locally, you can use the following commands:

```bash
# Starts the replica, running in the background
$ dfx start --background

# Deploys your canisters to the replica and generates your candid interface
$ dfx deploy
```
