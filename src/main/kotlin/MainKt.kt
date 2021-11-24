import kotlin.system.exitProcess

class MainKt {
    companion object{
        @JvmStatic fun main(args: Array<String>) {
//            if (args.size != 1) {
//                println("Run: java -jar https-simulator.jar")
//                exitProcess(1)
//            }
            HTTPS().simulate()

        }
    }
}
