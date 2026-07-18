# Spring Security Fundamentals

A hands-on learning project exploring database-backed authentication and authorization with **Spring Security 6**, **Spring Boot**, and **PostgreSQL** — built to go beyond the default in-memory login and understand how Spring Security actually wires authentication under the hood.

## Why this project

Most Spring Security tutorials stop at the auto-generated login form and a hardcoded in-memory user. This project skips that shortcut and implements the full chain manually:

- A `UserEntity` persisted in PostgreSQL instead of an in-memory user store
- A custom `UserDetailsService` that loads users from the database
- A custom `UserDetails` implementation (`UserPrincipal`) wrapping the entity
- An explicit `DaoAuthenticationProvider` wired to that service and a `BCryptPasswordEncoder`
- Stateless session management with `SessionCreationPolicy.STATELESS`
- Method-level authorization via `@PreAuthorize` and role checks

The goal is to understand *why* each piece exists, not just copy a working config.

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Java 26 |
| Framework | Spring Boot 4.1.0 |
| Security | Spring Security 6 (`spring-boot-starter-security`) |
| Persistence | Spring Data JPA + PostgreSQL |
| Password hashing | BCrypt |
| Config | `spring.config.import` + [dotenv-java](https://github.com/cdimascio/dotenv-java) for `.env` support |
| Build | Maven |
| Utilities | Lombok, Spring Boot DevTools |

## Getting Started

### Prerequisites

- JDK 26
- Maven (or use the included `mvnw` wrapper)
- A running PostgreSQL instance

## Security Configuration Notes

- **Password storage:** `BCryptPasswordEncoder` — never plaintext.
- **Authentication:** a custom `DaoAuthenticationProvider` is registered explicitly rather than relying on Spring Boot's autoconfiguration, using `AppUserDetailsService` as the user source.
- **Sessions:** configured as `STATELESS`, which is a deliberate inconsistency with the `formLogin()`/`httpBasic()` setup kept in this branch for comparison while experimenting — see [Roadmap](#roadmap).
- **CSRF:** currently disabled for easier endpoint testing during development.

## Roadmap

This is an active learning project. Planned next steps:

- [ ] Assign real roles per user (currently `UserPrincipal` hardcodes a single `USER` authority, so `/api/admin` isn't reachable yet)
- [ ] Move to stateless JWT authentication instead of the current session/form-login mix
- [ ] Add user registration endpoint with input validation
- [ ] Re-enable and properly configure CSRF protection
- [ ] Add integration tests using `spring-boot-starter-security-test`

## License

This project is for personal learning and portfolio purposes.
