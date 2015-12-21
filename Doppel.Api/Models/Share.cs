using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Doppel.Api.Models
{
    public class Share
    {
        public int Id { get; set; }
        public DateTime DateShared { get; set; }
        public string Message { get; set; }

        public virtual ReferenceItem Item { get; set; }
    }
}