package kripto;

import exceptions.*;
import extraUtil.AlertBox;
import extraUtil.ConfirmBox;
import extraUtil.Hashing;
import extraUtil.MD5;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.layout.BorderPane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.*;
import java.security.GeneralSecurityException;
import java.util.Base64;


public class LoginController {

    @FXML
    private TextField usernameTextField;
    @FXML
    private PasswordField passwordTextField;
    @FXML
    private BorderPane loginBorderPane;

    @FXML
    private TextField directoryTextField;

    @FXML
    public void findCert(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Find certificate");
        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("Certificate files", "*.crt")
        );
        File file = fileChooser.showOpenDialog(null);
        if (file != null) {
            directoryTextField.setText(file.getAbsolutePath());
        }
    }

    public void login(ActionEvent actionEvent) {
        try {
            validationOfData();
            mainApplication(actionEvent);
        } catch (UserNotFoundException e) {
            notifyIncorrectData(e);
        } catch (PasswordException e) {
            notifyIncorrectData(e);
        } catch (CertPathException e) {
            notifyIncorrectData(e);
        } catch (WrongCredentials e) {
            notifyIncorrectData(e);
        }
    }

    // todo - change this to use class Hashing -> rename to hashing
    private void validationOfData() throws UserNotFoundException, PasswordException, CertPathException, WrongCredentials {
        if (usernameTextField.getText().length() == 0) {
            throw new UserNotFoundException();
        } else if (passwordTextField.getText().length() == 0) {
            throw new PasswordException();
        } else if (directoryTextField.getText().length() == 0) {
            throw new CertPathException();
        } else {
            try {
//                BufferedReader br = new BufferedReader(new FileReader("users.txt"));
                FileInputStream fis = new FileInputStream("users.txt");
                byte[] data =  fis.readAllBytes();
                String users = new String(data);
                fis.close();
                if (!users.contains(usernameTextField.getText() + "#")) {
                    // if there is no username return exception
                    throw new WrongCredentials();
                } else {
                    // find index of line where is username
                    // users must have one new line at the end of file
                    int startIndex = users.indexOf(usernameTextField.getText() + "#");
                    int endIndex = users.indexOf('\n', startIndex);
                    String line = users.substring(startIndex, endIndex);
                    String [] s = line.split("#");

                    if(!Hashing.validateHashSHA256(passwordTextField.getText(), s[1])) {
                        throw new PasswordException();
                    } else {
                        System.out.println("Uspjesno ste se prijavili!");
                    }
                }
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            }
        }
    }

    public void cancelLogin(ActionEvent actionEvent) {
        ((Stage)loginBorderPane.getScene().getWindow()).close();
    }

    private void notifyIncorrectData(Exception e) {
        if (e instanceof UserNotFoundException) {
            AlertBox.display("Wrong username", "You have entered the wrong username!");
        } else if (e instanceof PasswordException) {
            AlertBox.display("Wrong password", "You have entered the wrong password!");
        } else if (e instanceof CertPathException) {
            AlertBox.display("Wrong path to cert", "You have entered the wrong path!");
        } else if (e instanceof WrongCredentials) {
            AlertBox.display("Wrong credencials", "Please input the correct credentials!");
        }
    }

    public void mainApplication(ActionEvent event) {
        try {
            Parent root = FXMLLoader.load(getClass().getResource("mainApp.fxml"));
            Scene scene = new Scene(root);
            Stage stage = new Stage();
            stage.setScene(scene);
            stage.setTitle("Main application");
            ((Stage) loginBorderPane.getScene().getWindow()).close();
            scene.getStylesheets().add("mainApp.css");
            stage.show();

            scene.getWindow().setOnCloseRequest(e -> {
                e.consume();
                Boolean answer = ConfirmBox.display("Warning!", "Are you sure you want to exit?");
                if (answer) {
                    stage.close();
                }
            });
        } catch (Exception e) {
            System.out.println("Exception in switching to main application");
        }
    }

}
