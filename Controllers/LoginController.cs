using Login.ApplictionDbContext;
using Login.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using static Login.DTO.AuthResponse;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Login.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ITokenService _tokenService;
        private readonly AppDbContext _db;

        public LoginController(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            RoleManager<IdentityRole> roleManager,
            ITokenService tokenService,
            AppDbContext db)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _tokenService = tokenService;
            _db = db;
        }

        // REGISTER (async, role-based)
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var existing = await _userManager.FindByEmailAsync(request.Email);
            if (existing != null)
                return Conflict(new { message = "Email already registered." });

            var user = new IdentityUser
            {
                UserName = request.Email,
                Email = request.Email
            };

            var result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
                return BadRequest(new { errors = result.Errors.Select(e => e.Description) });

            var role = string.IsNullOrWhiteSpace(request.Role) ? "User" : request.Role;
            if (!await _roleManager.RoleExistsAsync(role))
                return BadRequest(new { message = $"Role '{role}' does not exist." });

            var roleResult = await _userManager.AddToRoleAsync(user, role);
            if (!roleResult.Succeeded)
                return BadRequest(new { errors = roleResult.Errors.Select(e => e.Description) });

            return Ok(new { message = "User registered successfully.", userId = user.Id, role });
        }

        // LOGIN -> returns access + refresh token
        [HttpPost("login")]
        public async Task<ActionResult<TokenResponse>> Login([FromBody] LoginRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
                return Unauthorized(new { message = "Invalid credentials." });

            var check = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
            if (!check.Succeeded)
                return Unauthorized(new { message = "Invalid credentials." });

            var roles = await _userManager.GetRolesAsync(user);

            var (accessToken, accessExpires) = await _tokenService.CreateAccessTokenAsync(user, roles);
            var (refreshToken, refreshExpires) = await _tokenService.CreateRefreshTokenAsync(user);

            return Ok(new TokenResponse
            {
                AccessToken = accessToken,
                AccessTokenExpiresAt = accessExpires,
                RefreshToken = refreshToken,
                RefreshTokenExpiresAt = refreshExpires
            });
        }

        // REFRESH TOKEN
        [HttpPost("refresh")]
        public async Task<ActionResult<TokenResponse>> Refresh([FromBody] RefreshRequest request)
        {
            var stored = await _db.RefreshTokens
                .FirstOrDefaultAsync(x => x.Token == request.RefreshToken);

            if (stored == null || stored.Revoked || stored.ExpiresAt < DateTime.UtcNow)
                return Unauthorized(new { message = "Invalid refresh token." });

            var user = await _userManager.FindByIdAsync(stored.UserId);
            if (user == null)
                return Unauthorized(new { message = "Invalid refresh token." });

            var roles = await _userManager.GetRolesAsync(user);

            // Optionally rotate refresh tokens: revoke old and issue new
            stored.Revoked = true;
            await _db.SaveChangesAsync();

            var (accessToken, accessExpires) = await _tokenService.CreateAccessTokenAsync(user, roles);
            var (refreshToken, refreshExpires) = await _tokenService.CreateRefreshTokenAsync(user);

            return Ok(new TokenResponse
            {
                AccessToken = accessToken,
                AccessTokenExpiresAt = accessExpires,
                RefreshToken = refreshToken,
                RefreshTokenExpiresAt = refreshExpires
            });
        }

        // REVOKE refresh token (logout)
        [Authorize]
        [HttpPost("revoke")]
        public async Task<IActionResult> Revoke([FromBody] RefreshRequest request)
        {
            var stored = await _db.RefreshTokens
                .FirstOrDefaultAsync(x => x.Token == request.RefreshToken);

            if (stored == null)
                return NotFound(new { message = "Refresh token not found." });

            // Ensure only owner or admin can revoke
            var userId = _userManager.GetUserId(User);
            var isAdmin = User.IsInRole("Admin");
            if (stored.UserId != userId && !isAdmin)
                return Forbid();

            stored.Revoked = true;
            await _db.SaveChangesAsync();

            return Ok(new { message = "Refresh token revoked." });
        }

        // Example protected endpoint, role-based authorization
        [Authorize(Roles = "Admin")]
        [HttpGet("admin/ping")]
        public IActionResult AdminPing() => Ok(new { message = "Hello, Admin!" });

        [Authorize]
        [HttpGet("me")]
        public async Task<IActionResult> Me()
        {
            var userId = _userManager.GetUserId(User)!;
            var user = await _userManager.FindByIdAsync(userId);
            var roles = await _userManager.GetRolesAsync(user!);
            return Ok(new { userId, email = user!.Email, roles });
        }
    }
}

