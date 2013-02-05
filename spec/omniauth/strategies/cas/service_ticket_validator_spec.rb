describe OmniAuth::Strategies::CAS::ServiceTicketValidator do
  let(:strategy_stub) do
    stub('strategy stub',
      service_validate_url: 'https://example.org/serviceValidate'
    )
  end

  let(:provider_options) do
    stub('provider options',
      disable_ssl_verification?: false,
      ca_path: '/etc/ssl/certsZOMG',
      use_client_cert?: false
    )
  end

  let(:validator) do
    OmniAuth::Strategies::CAS::ServiceTicketValidator.new( strategy_stub, provider_options, '/foo', nil )
  end

  describe '#user_info' do
    subject do
      stub_request(:get, 'https://example.org/serviceValidate?').to_return(status: 200, body: '')
      validator.user_info
    end

    it 'should use the configured CA path' do
      provider_options.should_receive :ca_path

      subject
    end
  end
end

describe OmniAuth::Strategies::CAS::ServiceTicketValidator, 'with client_cert' do
  let(:strategy_stub) do
    stub('strategy stub',
      service_validate_url: 'https://example.org/serviceValidate'
    )
  end

  let(:provider_options) do
    stub('provider options',
      disable_ssl_verification?: false,
      ca_path: '/etc/ssl/certsZOMG',
      use_client_cert?: true,
      client_cert: '/etc/ssl/cert.cer',
      client_cert_key: '/etc/ssl/cert.key'
    )
  end

  let(:validator) do
    OmniAuth::Strategies::CAS::ServiceTicketValidator.new( strategy_stub, provider_options, '/foo', nil )
  end

  describe 'client_certificate' do
    subject do
      stub_request(:get, 'https://example.org/serviceValidate?').to_return(status: 200, body: '')
      validator.user_info
    end

    context 'use_client_cert?' do
      it 'should not add client_cert when use_client_cert? is false' do
        provider_options.should_receive(:use_client_cert?).and_return(false)
        validator.should_not_receive(:add_client_certificate)

        subject
      end

      it 'should add client_cert when use_client_cert? is true' do
        provider_options.should_receive(:use_client_cert?).and_return(true)
        validator.should_receive(:add_client_certificate)

        subject
      end
    end

    it 'should check the client_cert file & key exists' do
      File.should_receive(:exists?).with(provider_options.client_cert).and_return(true)
      File.should_receive(:exists?).with(provider_options.client_cert_key).and_return(false)

      subject
    end
  end
end
