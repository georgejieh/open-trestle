using System;

var total = Compute(2);
Console.WriteLine(total);

int Compute(int n) => n * 2;

class Helper
{
    public int Run() => Compute(1);
}
