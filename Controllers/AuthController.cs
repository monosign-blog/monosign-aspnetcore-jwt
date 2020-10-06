using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using MonoSign.JWT.Models;

namespace MonoSign.JWT.Controllers
{
	[ApiController]
	[Route("[controller]")]
	public class AuthController : ControllerBase
	{
		private readonly IConfiguration _configuration;

		public AuthController(IConfiguration configuration)
		{
			_configuration = configuration;
		}

		[HttpPost("login")]
		public IActionResult Login([FromBody] LoginModel model)
		{
			if (model.UserName == "MonoFor" && model.Password == "WeAreMono2017")
			{
				var secret = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_configuration["Jwt:Secret"]));
				var issuer = _configuration["Jwt:Issuer"];
				var audience = _configuration["Jwt:Audience"];
				var expiration = DateTime.UtcNow.AddMinutes(60);
				var tokenHandler = new JwtSecurityTokenHandler();
				var tokenDescriptor = new SecurityTokenDescriptor
				{
					Subject = new ClaimsIdentity(new Claim[]
					{
						new Claim(ClaimTypes.NameIdentifier, model.UserName),
					}),
					Expires = expiration,
					Issuer = issuer,
					Audience = audience,
					SigningCredentials = new SigningCredentials(secret, SecurityAlgorithms.HmacSha256Signature)
				};

				var token = tokenHandler.CreateToken(tokenDescriptor);
				var accessToken = tokenHandler.WriteToken(token);

				return Ok(new
				{
					AccessToken = accessToken
				});
			}

			return Unauthorized();
		}
	}
}