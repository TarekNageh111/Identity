using JWT_Backend.HelperBindings;
using JWT_Backend.UserIdentities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using RegistrationsLiberary.AuthModels;
using RegistrationsLiberary.Registerations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWT_Backend.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class AthenticationTestController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _identityRole;
        private readonly Jwt _jwt;
        public AthenticationTestController(UserManager<ApplicationUser> userManager, IOptions<Jwt> options, RoleManager<IdentityRole> identityRole)
        {
            _userManager = userManager;
            _jwt = options.Value;
            _identityRole = identityRole;
        }
        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterModel registerModel)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            if (await _userManager.FindByEmailAsync(registerModel.Email) is not null)
                return BadRequest(new Auth { Message = "Email Already registered" });

            if (await _userManager.FindByNameAsync(registerModel.UserName) is not null)
                return BadRequest(new Auth { Message = "UserName Already registered" });
            ApplicationUser applicationUser = new ApplicationUser
            {
                UserName = registerModel.UserName,
                FullName = registerModel.UserName,
                Email = registerModel.Email,
                CreationOn = DateTime.Now
            };
            var registered = await _userManager.CreateAsync(applicationUser, registerModel.Password);
            if (!registered.Succeeded)
            {
                string errors = string.Empty;
                foreach (var error in registered.Errors)
                    errors += $"{error.Description},";
                return BadRequest(new Auth { Message = errors });
            }
            var adduserToRole = await _userManager.AddToRoleAsync(applicationUser, "User");
            JwtSecurityToken getJwtSecurityToken = await GetJwtSecurityToken(applicationUser);
            return Ok(new Auth
            {
                Email = registerModel.Email,
                ExpiredOn = getJwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Message = "Registered Successfully",
                Token = new JwtSecurityTokenHandler().WriteToken(getJwtSecurityToken)
            });
        }
        [HttpPost]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var user = await _userManager.FindByEmailAsync(loginModel.Email);
            if (user is null || !await _userManager.CheckPasswordAsync(user, loginModel.Password))
                return BadRequest(new Auth { Message = "Email or password in correct!!" });
            var getToken = await GetJwtSecurityToken(user);
            return Ok(new Auth
            {
                Email = loginModel.Email,
                ExpiredOn = getToken.ValidTo,
                IsAuthenticated = true,
                Message = "Login Successfully",
                Token = new JwtSecurityTokenHandler().WriteToken(getToken)
            });
        }
        [HttpPost]
        public async Task<IActionResult> ForgetPassword([FromBody] ForgotPasswordModel forgotPasswordModel)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var user = await _userManager.FindByEmailAsync(forgotPasswordModel.Email);
            if (user is null)
                return BadRequest("Not found user with this email!!");

            var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);

            return Ok(resetToken);
        }
        [HttpPost]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordModel resetPasswordModel)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var user = await _userManager.FindByEmailAsync(resetPasswordModel.Email);
            if (user is null)
                return BadRequest("Not found user with this email!!");

            var resetPassword = await _userManager.ResetPasswordAsync(user, resetPasswordModel.Token, resetPasswordModel.NewPassword);
            if (!resetPassword.Succeeded)
            {
                string errors = string.Empty;
                foreach (var error in resetPassword.Errors)
                    errors += $"{error.Description},";
                return BadRequest(errors);
            }
            return Ok("Reset password successfully");
        }
        [Authorize]
        [HttpPost]
        public async Task<IActionResult> AddRoleToUser([FromBody] AddRoolModel addRoolModel)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByEmailAsync(addRoolModel.Email);

            if (user is null || !await _identityRole.RoleExistsAsync(addRoolModel.Role))
                return BadRequest("User or role not exist");

            if (await _userManager.IsInRoleAsync(user, addRoolModel.Role))
                return BadRequest($"{addRoolModel.Role} role already Assigned on user");

            var res = await _userManager.AddToRoleAsync(user, addRoolModel.Role);
            if (!res.Succeeded)
            {
                string errors = string.Empty;
                foreach (var error in res.Errors)
                    errors += $"{error.Description},";
                return BadRequest(new Auth { Message = errors });
            }
            return Ok(addRoolModel);
        }
        [HttpGet]
        public async Task<IActionResult> GetRolesOfUser(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user is null)
                return BadRequest(new Auth { Message = "Not found user" });
            var res = await _userManager.GetRolesAsync(user);
            return Ok(res.ToList());
        }
        [Authorize]
        [HttpGet]
        public IActionResult GetNames()
        {
            List<string> values = new List<string>()
            {
             "ahmed","mohamed","ali","AbdElrahman"
            };
            return Ok(values);
        }
        private async Task<JwtSecurityToken> GetJwtSecurityToken(ApplicationUser applicationUser)
        {
            var getClaimsOfUser = await _userManager.GetClaimsAsync(applicationUser);
            var getRolesOfUser = await _userManager.GetRolesAsync(applicationUser);
            List<Claim> claimRolesOfUser = new List<Claim>();
            foreach (var role in getRolesOfUser)
                claimRolesOfUser.Add(new Claim("roles", role));

            var claims = new Claim[]
            {
                new Claim(ClaimTypes.NameIdentifier,applicationUser.UserName),
                new Claim(ClaimTypes.Email,applicationUser.Email),
                new Claim(ClaimTypes.Name,applicationUser.FullName),
                new Claim("uid",applicationUser.Id),
            }.Union(getClaimsOfUser).Union(claimRolesOfUser);

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signInCredential = new SigningCredentials(key, algorithm: SecurityAlgorithms.HmacSha256);
            return new JwtSecurityToken(issuer: _jwt.Issuer, audience: _jwt.Audience, claims: claims,
                signingCredentials: signInCredential, expires: DateTime.UtcNow.AddHours(_jwt.DurationLifeTime));
        }
        [HttpGet]
        public async Task<IActionResult> GetRefreshToken(string email)
        {
            var applicationUser = await _userManager.FindByEmailAsync(email);
            if (applicationUser == null)
                return BadRequest(new Auth { Message = "User not found" });
            var getClaimsOfUser = await _userManager.GetClaimsAsync(applicationUser);
            var getRolesOfUser = await _userManager.GetRolesAsync(applicationUser);
            List<Claim> claimRolesOfUser = new List<Claim>();
            foreach (var role in getRolesOfUser)
                claimRolesOfUser.Add(new Claim("roles", role));

            var claims = new Claim[]
            {
                new Claim(ClaimTypes.NameIdentifier,applicationUser.UserName),
                new Claim(ClaimTypes.Email,applicationUser.Email),
                new Claim(ClaimTypes.Name,applicationUser.FullName),
                new Claim("uid",applicationUser.Id),
            }.Union(getClaimsOfUser).Union(claimRolesOfUser);

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signInCredential = new SigningCredentials(key, algorithm: SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(issuer: _jwt.Issuer, audience: _jwt.Audience, claims: claims,
                signingCredentials: signInCredential, expires: DateTime.UtcNow.AddHours(_jwt.DurationLifeTime));
            return Ok(new Auth
            {
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                ExpiredOn = jwtSecurityToken.ValidTo,
                Email = applicationUser.Email,
            });
        }
    }
}
