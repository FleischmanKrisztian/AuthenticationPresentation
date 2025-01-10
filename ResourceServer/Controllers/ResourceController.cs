using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ResourceServer.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ResourceController : ControllerBase
    {

        [HttpGet("Read")]
        [Authorize(Policy = "ReadScope")]
        public string Read()
        {
            return "Now I am reading!" + DateTime.UtcNow.ToString();
        }

        [HttpGet("Write")]
        [Authorize(Policy = "WriteScope")]
        public string Write()
        {
            return "Now I am writing!";
        }
    }
}
