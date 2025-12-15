namespace Login.DTO
{
    public class AuthResponse
    {
        public class RegisterRequest
        {
            public string Email { get; set; } = default!;
            public string Password { get; set; } = default!;
            public string? Role { get; set; } // Optional: "User" by default, can supply "Admin"
        }

        public class LoginRequest
        {
            public string Email { get; set; } = default!;
            public string Password { get; set; } = default!;
        }

        public class TokenResponse
        {
            public string AccessToken { get; set; } = default!;
            public DateTime AccessTokenExpiresAt { get; set; }
            public string RefreshToken { get; set; } = default!;
            public DateTime RefreshTokenExpiresAt { get; set; }
        }

        public class RefreshRequest
        {
            public string RefreshToken { get; set; } = default!;
        }
    }
}
