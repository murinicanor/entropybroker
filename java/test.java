class test
{
	public static void main(String [] args)
	{
		try
		{

			final int n = 10000;
			EntropybrokerConnector example = new EntropybrokerConnector("mauer");

			byte [] data = example.getData(n);

			System.out.print("Got: ");
			for(int loop=0; loop<n; loop++)
			{
				System.out.print("" + data[loop]);
				if (loop < (n - 1))
					System.out.print(", ");
			}
			System.out.println("");

			example.putData(new String("test").getBytes());
		}
		catch(Exception e)
		{
			System.out.println("Details: " + e.getMessage());
			System.out.println("Stack-trace:");
			for(StackTraceElement ste: e.getStackTrace())
			{
				System.out.println(" " + ste.getClassName() + ", "
						+ ste.getFileName() + ", "
						+ ste.getLineNumber() + ", "
						+ ste.getMethodName() + ", "
						+ (ste.isNativeMethod() ?
							"is native method" : "NOT a native method"));
			}
		}
	}
}
