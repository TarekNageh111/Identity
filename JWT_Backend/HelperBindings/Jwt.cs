namespace JWT_Backend.HelperBindings
{
    public class Jwt
    {
        public string Key {  get; set; }
        public string Issuer {  get; set; }
        public string Audience {  get; set; }
        public int DurationLifeTime {  get; set; }
    }
}
