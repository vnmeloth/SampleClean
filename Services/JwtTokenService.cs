using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

public class JwtTokenService
{
    private readonly string _secret;
    private readonly string _issuer;
    private readonly string _audience;

    //public JwtTokenService(string secret, string issuer, string audience)
    public JwtTokenService(string secret)
    {
        _secret = secret;
        //_issuer = issuer;
       // _audience = audience;
    }

    public string GenerateToken(string userId, string userName, bool isAdmin, int expiryMinutes = 60)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_secret);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim(JwtRegisteredClaimNames.Name, userName),
                new Claim("admin", isAdmin.ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString(), ClaimValueTypes.Integer64)
            }),
            Expires = DateTime.UtcNow.AddMinutes(expiryMinutes),
            //Issuer = _issuer,
            //Audience = _audience,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}
