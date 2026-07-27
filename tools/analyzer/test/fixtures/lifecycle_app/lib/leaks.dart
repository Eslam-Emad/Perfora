class AnimationController {
  void dispose() {}
}

class TextEditingController {
  void dispose() {}
}

class StreamSubscription<T> {
  void cancel() {}
}

class Worker {
  void dispose() {}
}

class ConsumerState {}

class LeakyConsumer extends ConsumerState {
  final animation = AnimationController();
}

class ChangeNotifier {}

class LeakyProvider extends ChangeNotifier {
  final fieldController = TextEditingController();
}

class Cubit {}

class LeakyCubit extends Cubit {
  late final StreamSubscription<String> subscription;
}

class GetxController {}

class LeakyGetxController extends GetxController {
  final Worker worker = Worker();
}
