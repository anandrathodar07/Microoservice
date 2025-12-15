using Login.Model;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace Login.Services
{
    public interface ITokenService
    {
        Task<(string token, DateTime expires)> CreateAccessTokenAsync(IdentityUser user, IList<string> roles);
        Task<(string token, DateTime expires)> CreateRefreshTokenAsync(IdentityUser user);
        ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);
    }
}
