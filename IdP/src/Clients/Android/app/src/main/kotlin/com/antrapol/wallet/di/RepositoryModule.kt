package com.antrapol.wallet.di

import com.antrapol.wallet.data.api.PqcIdentityApi
import com.antrapol.wallet.data.repository.RegistrationRepository
import com.antrapol.wallet.security.KeyManager
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * Hilt module providing repository dependencies.
 */
@Module
@InstallIn(SingletonComponent::class)
object RepositoryModule {

    @Provides
    @Singleton
    fun provideRegistrationRepository(
        api: PqcIdentityApi,
        keyManager: KeyManager
    ): RegistrationRepository {
        return RegistrationRepository(api, keyManager)
    }
}
