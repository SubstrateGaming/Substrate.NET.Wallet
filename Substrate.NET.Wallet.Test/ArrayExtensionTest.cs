using NUnit.Framework;
using Substrate.NET.Wallet.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Substrate.NET.Wallet.Test
{
    internal class ArrayExtensionTest
    {
        [Test]
        public void SubArray_WithNullInput_ShouldFail()
        {
            byte[] input = null;
            Assert.Throws<ArgumentNullException>(() => input.SubArray(0, 1));
        }

        [Test]
        public void SubArray_WithIncoherentInputs_ShouldFail() {
            byte[] input = { 0, 0, 0, 0 };
            Assert.Throws<ArgumentOutOfRangeException>(() => input.SubArray(10));
            Assert.Throws<ArgumentOutOfRangeException>(() => input.SubArray(-1));
            Assert.Throws<ArgumentOutOfRangeException>(() => input.SubArray(3, 2));
            Assert.Throws<ArgumentOutOfRangeException>(() => input.SubArray(3, 10));
        }
    }
}
