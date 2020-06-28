package br.com.jajm.auth.core;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import br.com.jajm.auth.domain.Usuario;
import br.com.jajm.auth.domain.UsuarioRepository;

@Service
public class JpaUserDetailsService implements UserDetailsService {
	
	@Autowired
	private UsuarioRepository usuarioRepository;

	@Transactional(readOnly = true)
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Usuario usuario = usuarioRepository.findByEmail(username)
					.orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado com o email informado!"));
		
		return new AuthUser(usuario, getAuthorities(usuario));
	}

	private Collection<? extends GrantedAuthority> getAuthorities(Usuario usuario) {
		return usuario.getGrupos().stream()
					.flatMap(grupo -> grupo.getPermissoes().stream())
					.map(permissao -> new SimpleGrantedAuthority(permissao.getNome().toUpperCase()))
					.collect(Collectors.toSet());
	}
	
	

}
