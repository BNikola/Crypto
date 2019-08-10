package controllers;

import extraUtil.exceptions.CertPathException;
import extraUtil.exceptions.PasswordException;
import extraUtil.exceptions.UserNotFoundException;
import extraUtil.exceptions.WrongCredentials;
import extraUtil.AlertBox;
import extraUtil.ConfirmBox;
import extraUtil.User;
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

import java.io.File;
import java.io.FileNotFoundException;


public class LoginController {
    // todo
    //  - verify certificate of login user

    private static final String PATH_TO_CERTS = "CRL/certs";
    private static final String CERTIFICATE_EXTENSION = "*.crt";

    @FXML
    private TextField usernameTextField;
    @FXML
    private PasswordField passwordTextField;
    @FXML
    private BorderPane loginBorderPane;

    @FXML
    private TextField certificateTextField;

    @FXML
    public void findCert(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Find certificate");
        fileChooser.setInitialDirectory(new File(PATH_TO_CERTS));
        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("Certificate files", CERTIFICATE_EXTENSION)
        );

        // this is for removing warning: GtkDialog mapped without a transient parent.
        File file = fileChooser.showOpenDialog((Stage)loginBorderPane.getScene().getWindow());
        if (file != null) {
            certificateTextField.setText(file.getAbsolutePath());
        }
    }

    public void login(ActionEvent actionEvent) {
        try {
            validationOfData();
            mainApplication(actionEvent);
        } catch (UserNotFoundException | PasswordException | CertPathException | WrongCredentials | FileNotFoundException e) {
            notifyIncorrectData(e);
        }
    }



    public void cancelLogin(ActionEvent actionEvent) {
        ((Stage)loginBorderPane.getScene().getWindow()).close();
    }



    public void mainApplication(ActionEvent event) {
        try {
            Parent root = FXMLLoader.load(getClass().getResource("../views/mainApp.fxml"));
            Scene scene = new Scene(root);
            Stage stage = new Stage();
            stage.setScene(scene);
            stage.setTitle("Main application");
            ((Stage) loginBorderPane.getScene().getWindow()).close();
            File f = new File("src/views/css/mainApp.css");
            scene.getStylesheets().add("file:///" + f.getAbsolutePath().replace("\\", "/"));

            stage.show();

            scene.getWindow().setOnCloseRequest(e -> {
                e.consume();
                boolean answer = ConfirmBox.display("Warning!", "Are you sure you want to exit?");
                if (answer) {
                    stage.close();
                }
            });
        } catch (Exception e) {
            System.out.println("Exception in switching to main application");
            e.printStackTrace();
        }
    }


    // region Private methods
    // validates user credentials, password, and path to certificate
    private void validationOfData() throws UserNotFoundException, PasswordException, CertPathException, WrongCredentials, FileNotFoundException {
        if (usernameTextField.getText().length() == 0) {
            throw new UserNotFoundException();
        } else if (passwordTextField.getText().length() == 0) {
            throw new PasswordException();
        } else if (certificateTextField.getText().length() == 0) {
            throw new CertPathException();
        }
        // validate path to user cert
        validatePathToFile(certificateTextField.getText());

        // create user for main app
        MainAppController.user = new User(usernameTextField.getText(), certificateTextField.getText(), passwordTextField.getText());
    }

    private void notifyIncorrectData(Exception e) {
        if (e instanceof UserNotFoundException) {
            AlertBox.display("Wrong username", "You have entered the wrong username!");
        } else if (e instanceof PasswordException) {
            AlertBox.display("Wrong password", "You have entered the wrong password!");
        } else if (e instanceof CertPathException) {
            AlertBox.display("Wrong path to cert", "You have entered the wrong path to certificate!");
        } else if (e instanceof WrongCredentials) {
            AlertBox.display("Wrong credencials", "Please input the correct credentials!");
        } else if (e instanceof FileNotFoundException) {
            AlertBox.display("Wrong path to cert", "That file does not exist");
        }
    }

    private void validatePathToFile(String path) throws FileNotFoundException {
        File file = new File(path);
        if (!file.exists()) {
            throw new FileNotFoundException();
        }
    }
    // endregion

}
