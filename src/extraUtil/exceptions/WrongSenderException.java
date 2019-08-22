package extraUtil.exceptions;

public class WrongSenderException extends Exception {
    public WrongSenderException() {
    }

    public WrongSenderException(String message) {
        super(message);
    }
}
