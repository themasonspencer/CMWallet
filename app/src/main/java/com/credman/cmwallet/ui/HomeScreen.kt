package com.credman.cmwallet.ui

import android.graphics.BitmapFactory
import android.util.Base64
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.credman.cmwallet.data.model.CredentialItem
import com.credman.cmwallet.data.model.PaymentMetadata

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    viewModel: HomeViewModel = viewModel()
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            CenterAlignedTopAppBar(
                title = {
                    Text(text = "CMWallet")
                }
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier.padding(innerPadding),
        ) {
            CredentialList(uiState.credentials)
        }
    }
}

@Composable
fun CredentialList(
    credentials: List<CredentialItem>
) {
    Column(
        Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        LazyColumn(
            modifier = Modifier.padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(15.dp)
        ) {
            credentials.forEach {
                item {
                    CredentialCard(cred = it)
                }
            }
        }
    }
}

@Composable
fun CredentialCard(
    cred: CredentialItem
) {
    val metadata = cred.metadata
    if (metadata is PaymentMetadata) {
        val cardArt = Base64.decode(metadata.icon, 0)
        Card(
            modifier = Modifier.size(350.dp, 210.dp),
            shape = CardDefaults.shape
        ) {
            Image(
                contentScale = ContentScale.Crop,
                modifier = Modifier.fillMaxSize(),
                bitmap = BitmapFactory.decodeByteArray(cardArt, /*offset=*/0, cardArt.size)!!
                    .asImageBitmap(),
                contentDescription = null
            )
        }
    }
}