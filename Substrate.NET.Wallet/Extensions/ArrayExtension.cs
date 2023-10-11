using System;

namespace Substrate.NET.Wallet.Extensions
{
    public static class ArrayExtension
    {
        /// <summary>
        /// Read an array from start index to end index
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="array"></param>
        /// <param name="start"></param>
        /// <param name="end"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static T[] SubArray<T>(this T[] array, int start, int end)
        {
            int length = end - start;
            if (length < 0)
                throw new InvalidOperationException($"{nameof(SubArray)} has start invalid start / end");

            T[] result = new T[length];
            Array.Copy(array, start, result, 0, length);
            return result;
        }

        public static T[] SubArray<T>(this T[] array, int start) => array.SubArray(start, array.Length);
    }
}
