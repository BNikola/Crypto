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
import kripto.Encryption;
import kripto.algs.CertUtil;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.nio.file.NotDirectoryException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;

public class MainAppController implements Initializable {

    public static User user;
    private static final String PATH_TO_ROOT_CERT = "/home/korisnik/Faks/Projektni/CRL/rootca.crt";
    private static final String PATH_TO_CRL = "/home/korisnik/Faks/Projektni/CRL/crl/rootcrl.pem";
    private static final String PATH_TO_CERTS = "CRL/certs";
    private static final String DEFAULT_DIR = System.getProperty("user.dir");
    private static final String INPUT_EXTENSION_FILTER = "*.java";
    private static final String CERTIFICATE_EXTENSION_FILTER = "*.crt";
    private static final String OUTPUT_EXTENSION_ENC_FILTER = "*.txt";
    private static final String OUTPUT_EXTENSION_ENC = ".txt";
    private static final String OUTPUT_EXTENSION_DEC = ".java";

    private X509Certificate rootCert;
    private List<String> reportList = new ArrayList<>();


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
    @FXML
    private TextField senderTextFieldDec;
    // endregion

    // todo
    //  - implement methods for encrypt and decrypt
    //  - figure out what to output for result
    //  - think about verify that returns boolean (Certificate verify)



    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        if (user != null) {
            userLabel.setText("Welcome: " + user.getUsername());
        }
        algorithmComboBox.getItems().add("AES");
        algorithmComboBox.getItems().add("CAMELLIA");
        algorithmComboBox.getItems().add("DES3");
        algorithmComboBox.getSelectionModel().selectFirst();
        try {
            rootCert = CertUtil.loadCert(PATH_TO_ROOT_CERT);
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }
    // region Encryption and decryption

    public void encrypt(ActionEvent event) {
        try {
            // validate fields and certificate
            validationOfDataEnc();
            // todo - maybe remove cert check (you can encrypt but others will not trust you)
            CertUtil.checkValidityOfCertificate(user.getCertificate(), rootCert, PATH_TO_CRL);

            // generate parameters for encryption
            String inputPath = filePathTextFieldEnc.getText();
            String fileName = outputFileNameTextFieldEnc.getText();
            String outputDir = outputPathTextFieldEnc.getText();
            String outputPath = outputDir + File.separator + fileName + OUTPUT_EXTENSION_ENC;
            String algorithmName = algorithmComboBox.getSelectionModel().getSelectedItem();
            String pathToUserCert = userCertTextFieldEnc.getText();


            // start encryption
            Encryption.encryption(inputPath, outputPath, algorithmName, pathToUserCert);

            // populate the list
            reportList.add("Username: " + user.getUsername());
            reportList.add("Symmetric algorithm used: " + algorithmName);
            reportList.add("Output file: " + fileName + OUTPUT_EXTENSION_ENC);
            reportList.add("Output location: " + outputDir);
            reportList.add("Status of encryption: " + "OK");
        } catch (NotDirectoryException | FieldMissingException | FileNotFoundException e) {
            notifyIncorrectData(e);
        } catch (SignatureException | CertificateOnCRLException | InvalidKeyException | NoSuchAlgorithmException | CertificateException e) {
            reportList.add("Status of encryption: " + "FAIL");
            AlertBox.display("Certificate error", "Your certificate is not valid");
        } catch (CRLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        reportList.add("Date: " + new Date());
        reportList.add("==================================================================");
        ObservableList<String> list = FXCollections.observableList(reportList);
        reportListViewEnc.setItems(list);
    }

    public void decrypt(ActionEvent event) {
        try {
            validationOfDataDec();
            CertUtil.checkValidityOfCertificate(user.getCertificate(), rootCert, PATH_TO_CRL);

            // generate parameters for decryption
            String inputPath = filePathTextFieldDec.getText();
            String outputDir = outputPathTextFieldDec.getText();
            String outputPath = outputDir;
            String sender = senderTextFieldDec.getText();
            Encryption.decryption(inputPath, outputPath, sender);
        } catch (NotDirectoryException | FieldMissingException | FileNotFoundException e) {
            notifyIncorrectData(e);
        } catch (SignatureException | CertificateOnCRLException | InvalidKeyException | NoSuchAlgorithmException | CertificateException e) {
            reportList.add("Status of decryption: " + "FAIL");
            AlertBox.display("Certificate error", "Your certificate is not valid");
        } catch (CRLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        reportList.add("Date: " + new Date());
        reportList.add("==================================================================");
        ObservableList<String> list = FXCollections.observableList(reportList);
        reportListViewDec.setItems(list);
    }
    // endregion
    // region Browse buttons

    public void findFileEnc(ActionEvent event) {
        findFile("Find file to encrypt", DEFAULT_DIR, "Java files", INPUT_EXTENSION_FILTER, filePathTextFieldEnc);
    }

    public void findFileDec(ActionEvent event) {
        findFile("Find file to decrypt", DEFAULT_DIR, "Text files", OUTPUT_EXTENSION_ENC_FILTER, filePathTextFieldDec);
    }

    public void findCert(ActionEvent actionEvent) {
        findFile("Find certificate", PATH_TO_CERTS, "Certificate files", CERTIFICATE_EXTENSION_FILTER, userCertTextFieldEnc);
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
                || senderTextFieldDec.getText().length() == 0
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
