using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Doppel.Api.Models
{
    public class ReferenceItem
    {
        public int Id { get; set; }
        public string Title { get; set; }
        public string URL { get; set; }
        public string Description { get; set; }
    }
}