package kripto;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.layout.StackPane;

public class MainAppController {

    @FXML
    private StackPane second;

    public void hideSecond(ActionEvent event) {
        second.setDisable(true);
    }
}
