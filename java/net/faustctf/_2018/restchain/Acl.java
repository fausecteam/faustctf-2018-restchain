package net.faustctf._2018.restchain;

import java.io.Serializable;

public class Acl implements Serializable {
	private final String acl;

	public Acl(String acl) {
		this.acl = acl;
	}

	public String getAclString() {
		return acl;
	}

	@Override
	public String toString() {
		return "Acl{" +
				"acl='" + acl + '\'' +
				'}';
	}
}
