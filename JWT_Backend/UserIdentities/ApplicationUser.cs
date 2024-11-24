using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace JWT_Backend.UserIdentities
{
    public class ApplicationUser : IdentityUser
    {
        [Required(ErrorMessage = "Full Name Is Required")]
        public string FullName { get; set; } = null!;
        public DateTime CreationOn {  get; set; }
    }
}
