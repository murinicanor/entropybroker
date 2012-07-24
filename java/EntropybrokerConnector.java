import java.net.Socket;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;

class EntropybrokerConnector
{
	String host;
	int port = 55225;
	final int maxBytes = 9999 / 8;
	Socket socket;
	InputStreamReader inputStream;
	OutputStreamWriter outputStream;

	EntropybrokerConnector(String host)
	{
		this.host = host;
	}

	EntropybrokerConnector(String host, int port)
	{
		this.host = host;
		this.port = port;
	}

	void writeData(OutputStreamWriter outputStream, String what) throws Exception
	{
		int whatLength = what.length();

		System.out.println("what: " + what);

		for(int loop=0; loop<whatLength; loop++)
			outputStream.write(what.charAt(loop));

		outputStream.flush();
	}

	void writeData(OutputStreamWriter outputStream, byte [] what) throws Exception
	{
		int whatLength = what.length;

		for(int loop=0; loop<whatLength; loop++)
			outputStream.write(what[loop]);

		outputStream.flush();
	}

	byte [] readData(InputStreamReader inputStream, int nBytes) throws Exception
	{
		byte [] output = new byte[nBytes];

		for(int loop=0; loop<nBytes; loop++)
		{
			int curByte = inputStream.read();

			if (curByte == -1)
				throw new Exception("short read after " + loop + " of " + nBytes + " bytes");

			output[loop] = (byte)curByte;
		}

		System.out.println("read: " + new String(output));

		return output;
	}

	void sendClientType(OutputStreamWriter outputStream) throws Exception
	{
		String clientType = "EntropybrokerConnector (Java) v0.1";
		String loginMessage = String.format("0006%04d", clientType.length()) + clientType;
		writeData(outputStream, loginMessage);
	}

	private void connect() throws Exception
	{
		socket = new Socket(host, port);
		inputStream  = new InputStreamReader (socket.getInputStream());
		outputStream = new OutputStreamWriter(socket.getOutputStream());

		// tell what kind of client this is
		sendClientType(outputStream);
	}

	byte [] getData(int bytes) throws Exception
	{
		if (bytes > maxBytes)
			throw new Exception("EntropybrokerConnector::getData, maximum " + maxBytes + " supported");

		if (socket == null || !socket.isConnected())
		{
			if (socket != null)
				socket.close();
			connect();
		}

		// request data
		String requestData = String.format("0001%04d", bytes * 8);
		writeData(outputStream, requestData);

		// get request reply
		byte [] reply = readData(inputStream, 8);
		String replyString = new String(reply);
		int nBits = Integer.valueOf(replyString.substring(4));
		int nBytes = (nBits + 7) / 8;

		if (replyString.substring(0, 3).equals("900") )
		{
			throw new Exception("Server is not refusing to send data");
		}

		return readData(inputStream, nBytes);
	}

	void putData(byte [] bytes) throws Exception
	{
		int whatLength = bytes.length;

		if (socket == null || !socket.isConnected())
		{
			if (socket != null)
				socket.close();
			connect();
		}

		if (whatLength > maxBytes)
		{
			whatLength = maxBytes;
			throw new Exception("EntropybrokerConnector::putData, maximum " + maxBytes + " supported");
		}

		// send send-request
		String requestData = String.format("0002%04d", whatLength * 8);
		writeData(outputStream, requestData);

		// get send-request reply
		byte [] reply = readData(inputStream, 8);
		String replyString = new String(reply);
		int nBits = Integer.valueOf(replyString.substring(4));
		int nBytes = (nBits + 7) / 8;

		if (replyString.substring(0, 4).equals("0001"))
		{
			writeData(outputStream, bytes);
		}
		else if (replyString.substring(0, 4).equals("9001"))
		{
			throw new Exception("Error code from server: all pools full, sleep " + replyString.substring(4) + " seconds");
		}
	}
}
