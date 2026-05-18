using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

[ApiController]
[Route("api/[controller]")]
public class JwtGeneratorController : ControllerBase
{
    private readonly IConfiguration _configuration;

    public JwtGeneratorController(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    [HttpPost("generate")]
    public IActionResult GenerateToken([FromBody] TokenRequest request)
    {
        try
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim("Name", request.Name),
                new Claim("EN", request.EmployeeNumber),
                new Claim(JwtRegisteredClaimNames.Sub, request.EmployeeNumber),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            if (!string.IsNullOrEmpty(request.Roles))
            {
                var roleList = request.Roles.Split(',', StringSplitOptions.RemoveEmptyEntries);
                foreach (var role in roleList)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role.Trim()));
                }
            }

            var issuedAt = DateTime.UtcNow;
            var expiresAt = issuedAt.AddDays(request.ExpirationDays);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                notBefore: issuedAt,
                expires: expiresAt,
                signingCredentials: creds
            );

            return Ok(new
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                IssuedAt = issuedAt,
                ExpiresAt = expiresAt
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new { Error = ex.Message });
        }
    }
}

public class TokenRequest
{
    public string Name { get; set; }
    public string EmployeeNumber { get; set; }
    public string Roles { get; set; }
    public int ExpirationDays { get; set; } = 365;
}