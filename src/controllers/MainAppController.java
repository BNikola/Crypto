package controllers;

import extraUtil.AlertBox;
import extraUtil.ConfirmBox;
import extraUtil.User;
import extraUtil.exceptions.*;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Cursor;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.BorderPane;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.FileNotFoundException;
import java.net.URL;
import java.nio.file.NotDirectoryException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;

public class MainAppController implements Initializable {

    public static User user;
    private static final String PATH_TO_CERTS = "CRL/certs";
    private static final String DEFAULT_DIR = System.getProperty("user.dir");
    private static final String CERTIFICATE_EXTENSION = "*.crt";
    private static final String OUTPUT_EXTENSION_ENC = "*.txt";


    // region FXML members
    @FXML
    private BorderPane mainBorderPane;
    @FXML
    private Label userLabel;
    @FXML
    private Label logOutLabel;
    @FXML
    private Tab encryptTab;
    @FXML
    private Tab decryptTab;
    @FXML
    private TextField filePathTextFieldEnc;
    @FXML
    private Button fileButtonEnc;
    @FXML
    private ComboBox<String> algorithmComboBox;
    @FXML
    private TextField outputPathTextFieldEnc;
    @FXML
    private Button outputDirButtonEnc;
    @FXML
    private TextField userCertTextFieldEnc;
    @FXML
    private Button certificateButtonEnc;
    @FXML
    private Button encryptButton;
    @FXML
    private TextField outputFileNameTextFieldEnc;
    @FXML
    private TextField filePathTextFieldDec;
    @FXML
    private Button fileButtonDec;
    @FXML
    private TextField outputPathTextFieldDec;
    @FXML
    private Button dirButton;
    @FXML
    private Button decryptButton;
    @FXML
    private ListView reportListViewEnc;
    @FXML
    private ListView reportListViewDec;
    // endregion

    // todo
    //  - implement methods for encrypt and decrypt
    //  - figure out what to output for result



    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        if (user != null) {
            userLabel.setText("Welcome: " + user.getUsername());
        }
        algorithmComboBox.getItems().add("AES");
        algorithmComboBox.getItems().add("CAMELLIA");
        algorithmComboBox.getItems().add("DES3");
        algorithmComboBox.getSelectionModel().selectFirst();
    }

    // region Encryption and decryption
    public void encrypt(ActionEvent event) {
        // todo
        //  - populate this list with something meaningful
        //  - validate all the paths
        try {
            validationOfDataEnc();
        } catch (NotDirectoryException | FieldMissingException | FileNotFoundException e) {
            notifyIncorrectData(e);
        }
        List<String> listA = new ArrayList<>();
        listA.add("Name");
        listA.add("This is some text for something");
        listA.add(new Date().toString());
        ObservableList<String> list = FXCollections.observableList(listA);
        reportListViewEnc.setItems(list);
    }

    public void decrypt(ActionEvent event) {
        try {
            validationOfDataDec();
        } catch (NotDirectoryException | FieldMissingException | FileNotFoundException e) {
            notifyIncorrectData(e);
        }
    }
    // endregion

    // region Browse buttons
    public void findFileEnc(ActionEvent event) {
        findFile("Find file to encrypt", DEFAULT_DIR, "Java files", "*.java", filePathTextFieldEnc);
    }

    public void findFileDec(ActionEvent event) {
        findFile("Find file to decrypt", DEFAULT_DIR, "Text files", OUTPUT_EXTENSION_ENC, filePathTextFieldDec);
    }

    public void findCert(ActionEvent actionEvent) {
        findFile("Find certificate", PATH_TO_CERTS, "Certificate files", CERTIFICATE_EXTENSION, userCertTextFieldEnc);
    }

    public void findDirToOutputEnc(ActionEvent event) {
        findDir("Find directory to output encrypted files", outputPathTextFieldEnc);
    }
    public void findDirToOutputDec(ActionEvent event) {
        findDir("Find directory to output decrypted files", outputPathTextFieldDec);
    }
    // endregion

    // region Log out
    public void logOut(MouseEvent mouseEvent) {
        backToLogIn(mouseEvent);
    }

    private void backToLogIn(MouseEvent event) {
        try {
            Parent root = FXMLLoader.load(getClass().getResource("../views/login.fxml"));
            Scene scene = new Scene(root);
            Stage stage = new Stage();
            stage.setScene(scene);
            stage.setTitle("Main application");
            ((Stage) mainBorderPane.getScene().getWindow()).close();
            File f = new File("src/views/css/login.css");
            scene.getStylesheets().add("file:///" + f.getAbsolutePath().replace("\\", "/"));
            stage.show();

            scene.getWindow().setOnCloseRequest(e -> {
                e.consume();
                boolean answer = ConfirmBox.display("Warning!", "Are you sure you want to log out?");
                if (answer) {
                    stage.close();
                }
            });
        } catch (Exception e) {
            System.out.println("Exception in switching to login screen");
        }
    }

    public void changeCursor(MouseEvent mouseEvent) {
        mainBorderPane.getScene().setCursor(Cursor.HAND);
    }

    public void revertCursor(MouseEvent mouseEvent) {
        mainBorderPane.getScene().setCursor(Cursor.DEFAULT);

    }
    // endregion

    // region Private methods
    private void findFile(String title, String startDir, String extensionFilter, String filter, TextField textField) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle(title);
        fileChooser.setInitialDirectory(new File(startDir));
        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter(extensionFilter, filter)
        );

        // this is for removing warning: GtkDialog mapped without a transient parent.
        File file = fileChooser.showOpenDialog(mainBorderPane.getScene().getWindow());
        if (file != null) {
            textField.setText(file.getAbsolutePath());
        }
    }

    private void findDir(String title, TextField textField) {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle(title);
        directoryChooser.setInitialDirectory(new File(MainAppController.DEFAULT_DIR));
        File file = directoryChooser.showDialog(mainBorderPane.getScene().getWindow());
        if (file != null) {
            textField.setText(file.getAbsolutePath());
        }
    }

    private void validatePathToFile(String path) throws FileNotFoundException {
        File file = new File(path);
        if (!file.exists()) {
            throw new FileNotFoundException();
        }
    }

    private void validatePathToDir(String path) throws FileNotFoundException, NotDirectoryException {
        File file = new File(path);
        if (!file.exists()) {
            throw new FileNotFoundException();
        } else if (!file.isDirectory()) {
            throw new NotDirectoryException(path);
        }
    }

    private void validationOfDataEnc() throws FileNotFoundException, FieldMissingException, NotDirectoryException {
        // if a field is empty
        if (filePathTextFieldEnc.getText().length() == 0
                || outputPathTextFieldEnc.getText().length() == 0
                || userCertTextFieldEnc.getText().length() == 0
                || outputFileNameTextFieldEnc.getText().length() == 0
        ) {
            throw new FieldMissingException();
        }
        // todo - change validate path to file to validate path to cert and throw new certException
        validatePathToFile(filePathTextFieldEnc.getText());
        validatePathToDir(outputPathTextFieldEnc.getText());
        validatePathToFile(userCertTextFieldEnc.getText());
    }

    private void validationOfDataDec() throws FileNotFoundException, FieldMissingException, NotDirectoryException {
        // if a field is empty
        if (filePathTextFieldDec.getText().length() == 0
                || outputPathTextFieldDec.getText().length() == 0
        ) {
            throw new FieldMissingException();
        }
        validatePathToFile(filePathTextFieldDec.getText());
        validatePathToDir(outputPathTextFieldDec.getText());
    }

    private void notifyIncorrectData(Exception e) {
        if (e instanceof FieldMissingException) {
            AlertBox.display("Missing field", "Please fill all fields");
        } else if (e instanceof CertPathException) {
            AlertBox.display("Wrong path to cert", "You have entered the wrong path to certificate!");
        } else if (e instanceof FileNotFoundException) {
            AlertBox.display("Wrong path to cert", "That file does not exist");
        } else if (e instanceof NotDirectoryException) {
            AlertBox.display("Wrong path to directory", "That directory does not exist");
        }
    }

    // endregion
}
