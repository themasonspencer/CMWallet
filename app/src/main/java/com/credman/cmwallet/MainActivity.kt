package com.credman.cmwallet

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.credman.cmwallet.ui.HomeScreen
import com.credman.cmwallet.ui.theme.CMWalletTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            CMWalletTheme {
                HomeScreen()
            }
        }
    }
}
