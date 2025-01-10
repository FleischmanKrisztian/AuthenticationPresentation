namespace AuthorizationServer
{
    public class UserStore
    {
        public List<User> Users { get; set; }

        public UserStore()
        {
            Users = new List<User>();
        }
    }
}