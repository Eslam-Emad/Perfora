class TextEditingController {
  void dispose() {}
}

class ChangeNotifier {}

class CleanProvider extends ChangeNotifier {
  final controller = TextEditingController();

  void dispose() {
    controller.dispose();
  }
}
