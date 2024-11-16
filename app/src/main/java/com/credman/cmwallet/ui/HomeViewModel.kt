package com.credman.cmwallet.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.credman.cmwallet.data.model.CredentialItem
import com.credman.cmwallet.data.repository.CredentialRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class HomeScreenUiState(
    val credentials: List<CredentialItem>
)

class HomeViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(HomeScreenUiState(emptyList()))
    val uiState: StateFlow<HomeScreenUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            CredentialRepository.credentials.collect { credentials ->
                _uiState.update { currentState ->
                    currentState.copy(
                        credentials = credentials
                    )
                }
            }
        }
    }

}