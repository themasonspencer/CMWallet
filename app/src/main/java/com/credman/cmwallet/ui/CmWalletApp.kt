package com.credman.cmwallet.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.Face
import androidx.compose.material3.Card
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CmWalletApp() {
    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            CenterAlignedTopAppBar(
                title = {
                    Text(text="CMWallet")
                }
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier.padding(innerPadding),
        ) {
            CredentialList()
        }
    }
}

@Composable
fun CredentialList() {
    Column(
        Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        LazyColumn(
            modifier = Modifier.padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(15.dp)
        ) {
            item {
                CredentialCard()
            }
            item {
                CredentialCard()
            }

        }
    }
}

@Composable
fun CredentialCard() {
    Card(
        Modifier.fillMaxWidth().height(160.dp),

    ) {
        Box(
            Modifier.fillMaxSize().background(brush = Brush.horizontalGradient(colors = listOf(Color(0x407D5280), Color(0x40EFB8C8))))
        ) {
            Row() {
                Image(
                    modifier = Modifier.padding(10.dp).size(80.dp, 80.dp),
                    imageVector = Icons.Filled.Face,
                    contentDescription = ""
                )
                Column(
                    modifier = Modifier.padding(10.dp)
                ) {
                    Text(
                        text = "My License",
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = "DMV",
                    )
                }
            }

        }

    }
}