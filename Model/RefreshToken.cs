namespace Login.Model
{
    public class RefreshToken
    {
        public int Id { get; set; }
        public string UserId { get; set; } = default!;
        public string Token { get; set; } = default!;
        public DateTime ExpiresAt { get; set; }
        public DateTime CreatedAt { get; set; }
        public bool Revoked { get; set; } = false;
    }
}
